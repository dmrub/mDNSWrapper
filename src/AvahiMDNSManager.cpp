/*
 * AvahiMDNSManager.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"

#include <cstddef>
#include <cstring>
#include <cassert>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <unordered_map>
#include <utility>
#include <atomic>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/address.h>
#include <avahi-common/alternative.h>
#include <avahi-common/defs.h>
#include <avahi-common/error.h>
#include <avahi-common/gccmacro.h>
#include <avahi-common/malloc.h>
#include <avahi-common/strlst.h>
#include <avahi-common/thread-watch.h>

namespace MDNS
{

namespace
{

class AvahiError: public std::runtime_error
{
public:

    AvahiError(const std::string &message)
        : std::runtime_error(message)
    {
    }

    virtual ~AvahiError() noexcept
    {
    }
};

class AvahiClientError: public AvahiError
{
public:
    AvahiClientError(const std::string & reason, AvahiClient * client)
        : AvahiError(formatError(reason, client))
        , error_(avahi_client_errno(client))
    {
    }

    AvahiClientError(const std::string & reason, int error)
        : AvahiError(formatError(reason, error))
        , error_(error)
    {
    }

    virtual ~AvahiClientError() noexcept
    {
    }

    int error()
    {
        return error_;
    }

    static std::string formatError(const std::string & what, AvahiClient *client)
    {
        return formatError(what, avahi_client_errno(client));
    }

    static std::string formatError(const std::string & what, int error)
    {
        std::ostringstream os;
        os << what << " error " << error << ": " << avahi_strerror(error);
        return os.str();
    }

private:
    int error_;
};

inline AvahiIfIndex toAvahiIfIndex(MDNSInterfaceIndex i)
{
    if (i == MDNS_IF_ANY)
    {
        return AVAHI_IF_UNSPEC;
    }
    return static_cast<AvahiIfIndex>(i);
}

inline MDNSInterfaceIndex fromAvahiIfIndex(AvahiIfIndex i)
{
    if (i == AVAHI_IF_UNSPEC)
    {
        return MDNS_IF_ANY;
    }
    return static_cast<MDNSInterfaceIndex>(i);
}

AvahiStringList * toAvahiStringList(const std::vector<std::string> & data)
{
    AvahiStringList * list = 0;

    for (auto it = data.begin(), et = data.end(); it != et; ++it)
    {
        list = avahi_string_list_add(list, it->c_str());
    }

    return list;
}

std::vector<std::string> fromAvahiStringList(AvahiStringList * list)
{
    std::vector < std::string > res;

    for (AvahiStringList * i = list; i != 0; i = avahi_string_list_get_next(i))
    {
        res.emplace_back(
                reinterpret_cast<const char *>(avahi_string_list_get_text(i)),
                avahi_string_list_get_size(i));
    }

    return res;
}

inline const char * toAvahiStr(const std::string & str)
{
    return str.empty() ? 0 : str.c_str();
}

inline std::string fromAvahiStr(const char *str)
{
    return str ? str : "";
}

class AvahiPollGuard
{
public:

    AvahiPollGuard(AvahiThreadedPoll *threadedPoll)
        : threadedPoll_(threadedPoll)
    {
        avahi_threaded_poll_lock(threadedPoll_);
    }

    ~AvahiPollGuard()
    {
        avahi_threaded_poll_unlock(threadedPoll_);
    }

private:
    AvahiThreadedPoll *threadedPoll_;
};

class ServiceResolverGuard
{
public:
    ServiceResolverGuard(AvahiServiceResolver *resolver)
        : resolver_(resolver)
    {
    }

    ~ServiceResolverGuard()
    {
        avahi_service_resolver_free(resolver_);
    }

private:
    AvahiServiceResolver *resolver_;
};


} // unnamed namespace

class MDNSManager::PImpl
{
public:

    struct AvahiServiceRecord
    {
        std::string serviceName;
        AvahiEntryGroup *group;
        std::vector<MDNSService> services;
        size_t nextToRegister;
        MDNSManager::PImpl &pimpl;

        AvahiServiceRecord(const std::string &name, MDNSManager::PImpl &pimpl)
            : serviceName(name), group(0), services(), nextToRegister(0), pimpl(pimpl)
        {
        }

        ~AvahiServiceRecord()
        {
            if (group)
            {
                avahi_entry_group_reset(group);
                avahi_entry_group_free(group);
            }
        }

        void selectAlternativeServiceName()
        {
            std::string oldName = std::move(serviceName);
            char * altName = avahi_alternative_service_name(oldName.c_str());
            if (altName)
            {
                serviceName = altName;
                avahi_free(altName);
                if (pimpl.alternativeServiceNameHandler)
                    pimpl.alternativeServiceNameHandler(serviceName, oldName);
            }
            else
            {
                serviceName = std::move(oldName);
                if (pimpl.alternativeServiceNameHandler)
                    pimpl.alternativeServiceNameHandler(serviceName, serviceName);
            }
        }

        void resetServices()
        {
            if (group)
            {
                avahi_entry_group_reset(group);
                if (services.empty())
                {
                    avahi_entry_group_free(group);
                    group = 0;
                }
                nextToRegister = 0;
            }
        }

        static void entryGroupCB(AvahiEntryGroup *g, AvahiEntryGroupState state,
                AVAHI_GCC_UNUSED void *userdata)
        {
            AvahiServiceRecord * self =
                reinterpret_cast<AvahiServiceRecord*>(userdata);
            assert(g == self->group || self->group == 0);

            if (self->group == 0)
            {
                self->group = g;
            }

            switch (state)
            {
                case AVAHI_ENTRY_GROUP_ESTABLISHED:
                    /* The entry group has been established successfully */
                    //fprintf(stderr, "Service '%s' successfully established.\n", name);
                    break;

                case AVAHI_ENTRY_GROUP_COLLISION:
                {
                    /* A service name collision with a remote service
                     * happened. Let's pick a new name */
                    self->selectAlternativeServiceName();
                    /* And recreate the services */
                    avahi_entry_group_reset(self->group);
                    self->nextToRegister = 0;
                    self->registerMissingServices(avahi_entry_group_get_client(g), /*callFromThread=*/true);
                    break;
                }

                case AVAHI_ENTRY_GROUP_FAILURE:
                    self->pimpl.avahiError("Entry group failure",
                                     avahi_entry_group_get_client(g));
                    self->pimpl.stopThread(/*callFromThread=*/true);
                    break;
                case AVAHI_ENTRY_GROUP_UNCOMMITED:
                case AVAHI_ENTRY_GROUP_REGISTERING:
                    break;
                default:
                    self->pimpl.error("Unexpected AvahiEntryGroupState value");
            }
        }

        bool registerMissingServices(AvahiClient *client, bool callFromThread)
        {
            assert(client);

            if (services.empty())
            {
                avahi_entry_group_reset(group);
                avahi_entry_group_free(group);
                nextToRegister = 0;
                group = 0;
                return true;
            }

            if (!group)
            {
                if (!(group = avahi_entry_group_new(client, &entryGroupCB,
                                                    reinterpret_cast<void*>(this))))
                {
                    pimpl.avahiError("avahi_entry_group_new() failed : ",
                                     client);
                    pimpl.stopThread(callFromThread);
                    return false;
                }
            }

            //resetting and resubmitting all
            if (services.size() > 0 && nextToRegister > 0)
            {
                avahi_entry_group_reset(group);
                nextToRegister = 0;
            }

            bool repeatRegistration;
            bool needToCommit;

            do
            {
                repeatRegistration = false;
                needToCommit = false;
                while (nextToRegister < services.size())
                {
                    int error = registerService(client, services[nextToRegister], callFromThread);

                    if (error == AVAHI_OK)
                    {
                        needToCommit = true;
                    }
                    else if (error == AVAHI_ERR_COLLISION)
                    {
                        selectAlternativeServiceName();
                        avahi_entry_group_reset(group);
                        nextToRegister = 0;
                        repeatRegistration = true;
                        break;
                    }
                    else
                    {
                        return false;
                    }
                    ++nextToRegister;
                }
            } while (repeatRegistration);


            if (!needToCommit)
            {
                return true;
            }

            int ret = avahi_entry_group_commit(group);
            if (ret < 0)
            {
                pimpl.avahiError("Failed to commit entry group", ret);
                pimpl.stopThread(callFromThread);
                return false;
            }
            return true;
        }

        /**
         * Returns avahi error code
         */
        int registerService(AvahiClient *client, const MDNSService &service, bool callFromThread)
        {
            assert(client);
            assert(group);

            AvahiStringList *txtRecords = toAvahiStringList(service.getTxtRecords());

            int error = avahi_entry_group_add_service_strlst(
                    group, toAvahiIfIndex(service.getInterfaceIndex()),
                    AVAHI_PROTO_UNSPEC, (AvahiPublishFlags) 0, serviceName.c_str(),
                    toAvahiStr(service.getType()), toAvahiStr(service.getDomain()),
                    toAvahiStr(service.getHost()), service.getPort(), txtRecords);

            avahi_string_list_free(txtRecords);

            if (error == AVAHI_ERR_COLLISION)
            {
                return false;
            }

            if (error < 0)
            {
                pimpl.avahiError("avahi_entry_group_add_service_strlst() failed", error);
                pimpl.stopThread(callFromThread);
                return error;
            }

            std::string subtype;
            for (auto it = service.getSubtypes().begin(), et = service.getSubtypes().end();
                    it != et; ++it)
            {
                subtype = (*it+"._sub."+service.getType());
                error = avahi_entry_group_add_service_subtype(
                        group, toAvahiIfIndex(service.getInterfaceIndex()),
                        AVAHI_PROTO_UNSPEC, (AvahiPublishFlags) 0,
                        serviceName.c_str(), toAvahiStr(service.getType()),
                        toAvahiStr(service.getDomain()), subtype.c_str());
                if (error < 0)
                {
                    pimpl.avahiError("avahi_entry_group_add_service_subtype() failed: subtype: "+subtype, error);
                    pimpl.stopThread(callFromThread);
                    return error;
                }
            }
            return AVAHI_OK;
        }
    };

    typedef std::unordered_map<std::string, AvahiServiceRecord> AvahiServiceRecordMap;

    struct AvahiBrowserRecord
    {
        MDNSServiceBrowser::Ptr handler;
        std::vector<AvahiServiceBrowser *> serviceBrowsers;
        MDNSManager::PImpl &pimpl;

        AvahiBrowserRecord(const MDNSServiceBrowser::Ptr &handler, MDNSManager::PImpl &pimpl)
            : handler(handler), serviceBrowsers(), pimpl(pimpl)
        { }

        ~AvahiBrowserRecord()
        {
            for (auto it = serviceBrowsers.begin(), iend = serviceBrowsers.end(); it != iend; ++it)
            {
                avahi_service_browser_free(*it);
            }
        }

        static void resolveCB(
                AvahiServiceResolver *r,
                AVAHI_GCC_UNUSED AvahiIfIndex interface,
                AVAHI_GCC_UNUSED AvahiProtocol protocol,
                AvahiResolverEvent event,
                const char *name,
                const char *type,
                const char *domain,
                const char *host_name,
                const AvahiAddress *address,
                uint16_t port,
                AvahiStringList *txt,
                AvahiLookupResultFlags flags,
                AVAHI_GCC_UNUSED void* userdata)
        {
            assert(r);
            ServiceResolverGuard g(r);

            /* Called whenever a service has been resolved successfully or timed out */

            AvahiBrowserRecord * self =
                reinterpret_cast<AvahiBrowserRecord*>(userdata);
            AvahiClient * client = avahi_service_resolver_get_client(r);

            switch (event)
            {
                case AVAHI_RESOLVER_FAILURE:
                    self->pimpl.avahiError("Failed to resolve service '"+fromAvahiStr(name)+
                                           "' of type '"+fromAvahiStr(type)+
                                           "' in domain '"+fromAvahiStr(domain)+"'", client);
                    break;

                case AVAHI_RESOLVER_FOUND:
                {
                    if (self->handler)
                    {
                        MDNSService service;
                        service.setInterfaceIndex(fromAvahiIfIndex(interface));
                        service.setName(fromAvahiStr(name));
                        service.setType(fromAvahiStr(type));
                        service.setDomain(fromAvahiStr(domain));
                        service.setHost(fromAvahiStr(host_name));
                        service.setPort(port);
                        service.setTxtRecords(fromAvahiStringList(txt));

                        self->handler->onNewService(service);
                    }
                }
            }
        }

        /**
         * Checks if type is of form 'XXX._tcp' or 'XXX._udp'
         */
        static bool isValidType(const char *type)
        {
            if (!type)
                return false;
            const int tlen = strlen(type);
            return (tlen >= 5 &&
                    type[tlen-5] == '.' &&
                    type[tlen-4] == '_' &&
                    ((type[tlen-3] == 't' && type[tlen-2] == 'c' && type[tlen-1] == 'p') ||
                            (type[tlen-3] == 'u' && type[tlen-2] == 'd' && type[tlen-1] == 'p')));
        }

        static void browseCB(
            AvahiServiceBrowser *b,
            AvahiIfIndex interface,
            AvahiProtocol protocol,
            AvahiBrowserEvent event,
            const char *name,
            const char *type,
            const char *domain,
            AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
            void* userdata)
        {
            AvahiBrowserRecord * self =
                reinterpret_cast<AvahiBrowserRecord*>(userdata);
            AvahiClient * client = avahi_service_browser_get_client(b);
            switch (event)
            {
                case AVAHI_BROWSER_FAILURE:

                    self->pimpl.avahiError("Browser failure", client);
                    self->pimpl.stopThread(/*callFromThread=*/true);
                    return;

                case AVAHI_BROWSER_NEW:
                    {
                        //fprintf(stderr, "(Browser) NEW: service '%s' of type '%s' in domain '%s'\n", name, type, domain);

                        // check if type is 'XXX._tcp' or 'XXX._udp'

                        if (isValidType(type))
                        {

                            /* We ignore the returned resolver object. In the callback
                               function we free it. If the server is terminated before
                               the callback function is called the server will free
                               the resolver for us. */

                            if (!(avahi_service_resolver_new(client, interface, protocol, name, type, domain, AVAHI_PROTO_UNSPEC,
                                                             (AvahiLookupFlags)0, resolveCB, userdata)))
                                self->pimpl.avahiError("Failed to resolve service '" + fromAvahiStr(name) + "'", client);
                        }
                        else
                        {
                            // this is service type browsing
                            if (self->handler)
                            {
                                MDNSService service;
                                service.setInterfaceIndex(fromAvahiIfIndex(interface));
                                service.setType(fromAvahiStr(name)+"."+fromAvahiStr(type));
                                service.setDomain(fromAvahiStr(domain));

                                self->handler->onNewService(service);
                            }
                        }
                    }
                    break;

                case AVAHI_BROWSER_REMOVE:
                    //fprintf(stderr, "(Browser) REMOVE: service '%s' of type '%s' in domain '%s'\n", name, type, domain);
                    if (self->handler)
                    {
                        if (isValidType(type))
                            self->handler->onRemovedService(fromAvahiStr(name), fromAvahiStr(type), fromAvahiStr(domain));
                        else
                            self->handler->onRemovedService("", fromAvahiStr(name)+"."+fromAvahiStr(type), fromAvahiStr(domain));
                    }
                    break;

                case AVAHI_BROWSER_ALL_FOR_NOW:
                case AVAHI_BROWSER_CACHE_EXHAUSTED:
                    //fprintf(stderr, "(Browser) %s\n", event == AVAHI_BROWSER_CACHE_EXHAUSTED ? "CACHE_EXHAUSTED" : "ALL_FOR_NOW");
                    break;
            }

        }
    };

    typedef std::unordered_map<MDNSServiceBrowser::Ptr, AvahiBrowserRecord> AvahiBrowserRecordMap;

    AvahiClient *client;
    bool clientRunning;
    std::atomic<bool> threadRunning;
    AvahiThreadedPoll *threadedPoll;
    MDNSManager::AlternativeServiceNameHandler alternativeServiceNameHandler;
    MDNSManager::ErrorHandler errorHandler;

    AvahiServiceRecordMap serviceRecords;
    AvahiBrowserRecordMap browserRecords;
    std::vector<std::string> errorLog;

    PImpl()
        : client(0), clientRunning(false), threadRunning(false), threadedPoll(0), serviceRecords()
    {
        if (!(threadedPoll = avahi_threaded_poll_new()))
        {
            throw AvahiError("Could not allocate Avahi threaded poll");
        }

        threadRunning = true;

        int error;

        if (!(client = avahi_client_new(avahi_threaded_poll_get(threadedPoll),
                                        (AvahiClientFlags) 0, clientCB, this,
                                        &error)))
        {
            avahi_threaded_poll_free(threadedPoll);
            throw AvahiClientError("Could not allocate Avahi client", error);
        }
    }

    ~PImpl()
    {
        stop();

        // Remove all browser and service records before freeing client
        // otherwise group and browser pointers are invalidated
        serviceRecords.clear();
        browserRecords.clear();
        avahi_client_free(client);
        avahi_threaded_poll_free(threadedPoll);
    }

    void run()
    {
        if (avahi_threaded_poll_start(threadedPoll) < 0)
        {
            throw AvahiError("Could not start Avahi threaded poll");
        }
    }

    void stopThread(bool callFromThread)
    {
        if (threadRunning.exchange(false))
        {
            if (callFromThread)
                avahi_threaded_poll_quit(threadedPoll);
            else
            {
                // all calls to stopThread are guarded, so we need to unlock first
                avahi_threaded_poll_unlock(threadedPoll);
                avahi_threaded_poll_stop(threadedPoll);
                avahi_threaded_poll_lock(threadedPoll);
            }
        }
    }

    void stop()
    {
        if (threadRunning.exchange(false))
        {
            avahi_threaded_poll_stop(threadedPoll);
        }
    }

    void registerMissingServices(AvahiClient *client, bool callFromThread)
    {
        if (!clientRunning)
            return;
        for (auto it = serviceRecords.begin(), eit = serviceRecords.end();
                it != eit; ++it)
        {
            it->second.registerMissingServices(client, callFromThread);
        }
    }

    void resetServices()
    {
        for (auto it = serviceRecords.begin(), eit = serviceRecords.end();
                it != eit; ++it)
        {
            it->second.resetServices();
        }
    }

    void error(std::string errorMsg)
    {
        if (errorHandler)
            errorHandler(errorMsg);
        errorLog.push_back(std::move(errorMsg));
    }

    void avahiError(const std::string & what, int errorCode)
    {
        std::ostringstream os;
        os << what << " error " << errorCode << ": " << avahi_strerror(errorCode);
        error(os.str());
    }

    void avahiError(const std::string & what, AvahiClient *client)
    {
        avahiError(what, avahi_client_errno(client));
    }

    static void clientCB(AvahiClient *client, AvahiClientState state,
            AVAHI_GCC_UNUSED void * userdata)
    {
        PImpl *self = (PImpl*) userdata;

        assert(client);

        switch (state)
        {
            case AVAHI_CLIENT_S_RUNNING:
                self->clientRunning = true;
                /* The server has startup successfully and registered its host
                 * name on the network, so it's time to create our services */
                self->registerMissingServices(client, /*callFromThread=*/true);
                break;

            case AVAHI_CLIENT_FAILURE:
            {
                self->avahiError("Client failure", client);
                self->stopThread(/*callFromThread=*/true);
                break;
            }
            case AVAHI_CLIENT_S_COLLISION:
                /* Let's drop our registered services. When the server is back
                 * in AVAHI_SERVER_RUNNING state we will register them
                 * again with the new host name. */
            case AVAHI_CLIENT_S_REGISTERING:
                /* The server records are now being established. This
                 * might be caused by a host name change. We need to wait
                 * for our own records to register until the host name is
                 * properly established. */
                self->resetServices();
                break;

            case AVAHI_CLIENT_CONNECTING:
                break;
            default:
                self->error("Unexpected AvahiClient state");
        }
    }

    void registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                const std::string &type,
                                const std::string &domain,
                                const MDNSServiceBrowser::Ptr & browser)
    {
        MDNSManager::PImpl::AvahiBrowserRecord *browserRec = 0;
        auto it = browserRecords.find(browser);
        if (it == browserRecords.end())
        {
            it = browserRecords.insert(
                    std::make_pair(browser,
                        MDNSManager::PImpl::AvahiBrowserRecord(browser, *this))).first;
        }
        browserRec = &it->second;

        AvahiServiceBrowser *sb = avahi_service_browser_new(client,
                                                            toAvahiIfIndex(interfaceIndex),
                                                            AVAHI_PROTO_UNSPEC,
                                                            toAvahiStr(type),
                                                            toAvahiStr(domain),
                                                            (AvahiLookupFlags)0,
                                                            MDNSManager::PImpl::AvahiBrowserRecord::browseCB,
                                                            browserRec);

        if (!sb)
        {
            // remove empty records
            if (browserRec->serviceBrowsers.empty())
                browserRecords.erase(it);
            throw AvahiClientError("avahi_service_browser_new() failed", client);
        }
        browserRec->serviceBrowsers.push_back(sb);
    }

};

MDNSManager::MDNSManager()
    : pimpl_(new MDNSManager::PImpl)
{
}

MDNSManager::~MDNSManager()
{
}

bool MDNSManager::isAvailable()
{
    return true;
}

void MDNSManager::run()
{
    pimpl_->run();
}

void MDNSManager::stop()
{
    pimpl_->stop();
}

void MDNSManager::setAlternativeServiceNameHandler(MDNSManager::AlternativeServiceNameHandler handler)
{
    AvahiPollGuard g(pimpl_->threadedPoll);
    pimpl_->alternativeServiceNameHandler = handler;
}

void MDNSManager::setErrorHandler(MDNSManager::ErrorHandler handler)
{
    AvahiPollGuard g(pimpl_->threadedPoll);
    pimpl_->errorHandler = handler;
}

void MDNSManager::registerService(MDNSService &service)
{
    if (service.getId() != MDNSService::NO_SERVICE)
        throw std::logic_error("Service was already registered");

    AvahiPollGuard g(pimpl_->threadedPoll);

    MDNSManager::PImpl::AvahiServiceRecord *serviceRec = 0;
    auto it = pimpl_->serviceRecords.find(service.getName());
    if (it == pimpl_->serviceRecords.end())
    {
        it = pimpl_->serviceRecords.insert(
                std::make_pair(service.getName(),
                    MDNSManager::PImpl::AvahiServiceRecord(service.getName(), *pimpl_))).first;
    }
    serviceRec = &it->second;

    const MDNSService::Id serviceId = getNewServiceId();
    setServiceId(service, serviceId);

    serviceRec->services.push_back(service);
    pimpl_->registerMissingServices(pimpl_->client, /*callFromThread=*/false);
}

void MDNSManager::unregisterService(MDNSService &service)
{
    if (service.getId() == MDNSService::NO_SERVICE)
        throw std::logic_error("Service was not registered");

    AvahiPollGuard g(pimpl_->threadedPoll);

    for (auto it = pimpl_->serviceRecords.begin(), eit = pimpl_->serviceRecords.end(); it != eit; ++it)
    {
        bool changed = false;
        for (auto jt = it->second.services.begin(); jt != it->second.services.end(); )
        {
            if (jt->getId() == service.getId())
            {
                jt = it->second.services.erase(jt);
                changed = true;
            }
            else
                ++jt;
        }
        if (changed)
        {
            //it->second.resetServices();
            it->second.registerMissingServices(pimpl_->client, /*callFromThread=*/false);
        }
    }
}

void MDNSManager::registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                         const std::string &type,
                                         const std::vector<std::string> *subtypes,
                                         const std::string &domain,
                                         const MDNSServiceBrowser::Ptr & browser)
{
    if (type.empty())
        throw std::logic_error("type argument can't be empty");

    AvahiPollGuard g(pimpl_->threadedPoll);

    if (subtypes)
    {
        std::string subtype;
        for (auto it = subtypes->begin(), eit = subtypes->end(); it != eit; ++it)
        {
            subtype = it->empty() ? type : (*it+"._sub."+type);
            pimpl_->registerServiceBrowser(interfaceIndex, subtype, domain, browser);
        }
    }
    else
    {
        pimpl_->registerServiceBrowser(interfaceIndex, type, domain, browser);
    }
}

void MDNSManager::unregisterServiceBrowser(const MDNSServiceBrowser::Ptr & browser)
{
    AvahiPollGuard g(pimpl_->threadedPoll);

    pimpl_->browserRecords.erase(browser);
}

std::vector<std::string> MDNSManager::getErrorLog()
{

    std::vector<std::string> result;
    {
        AvahiPollGuard g(pimpl_->threadedPoll);
        result.swap(pimpl_->errorLog);
    }
    return result;
}

} // namespace MDNS
