/*
 * BonjourMDNSManager.cpp
 *
 *  Created on: Jan 15, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"

#ifdef _WIN32
#include <process.h>
typedef int pid_t;
#define getpid _getpid
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "dnssd.lib")
#else
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

#include <dns_sd.h>
#include <thread>
#include <mutex>
#include <atomic>

#include <cerrno>
#include <cstring>
#include <cstddef>
#include <cassert>
#include <cstdint>
#include <cctype>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <algorithm>
#include <utility>

#include <iostream>

namespace MDNS
{

namespace
{

typedef std::recursive_mutex ImplMutex;
typedef std::lock_guard<std::recursive_mutex> ImplLockGuard;

inline bool strEndsWith(const std::string &str, const std::string &strEnd)
{
    if (strEnd.size() > str.size())
        return false;
    if (strEnd.size() == str.size())
        return strEnd == str;
    std::string::const_reverse_iterator i = str.rbegin();
    std::string::const_reverse_iterator i1 = strEnd.rbegin();
    while (i1 != strEnd.rend())
    {
        if (*i != *i1)
            return false;
        ++i;
        ++i1;
    }
    return true;
}

inline void removeTrailingDot(std::string &str)
{
    if (str.length() > 0 && str[str.length()-1] == '.')
    {
        str.resize(str.length()-1);
    }
}

inline uint32_t toDnsSdInterfaceIndex(MDNSInterfaceIndex i)
{
    if (i == MDNS_IF_ANY)
    {
        return kDNSServiceInterfaceIndexAny;
    }
    return static_cast<uint32_t>(i);
}

inline MDNSInterfaceIndex fromDnsSdInterfaceIndex(uint32_t i)
{
    if (i == kDNSServiceInterfaceIndexAny)
    {
        return MDNS_IF_ANY;
    }
    return static_cast<MDNSInterfaceIndex>(i);
}


inline const char * toDnsSdStr(const std::string & str)
{
    return str.empty() ? 0 : str.c_str();
}

inline std::string fromDnsSdStr(const char *str)
{
    return str ? str : "";
}

std::string encodeTxtRecordData(const std::vector<std::string> & fields, bool & invalidFields)
{
    std::string str;
    invalidFields = false;

    for (auto it = fields.begin(), iend = fields.end(); it != iend; ++it)
    {
        if (it->length() > 255)
        {
            invalidFields = true;
            continue;
        }
        if (it->find_first_of('\0', 0) != std::string::npos)
        {
            invalidFields = true;
            continue;
        }

        str += (char)it->length();
        str += *it;
    }

    return str;
}

std::vector<std::string> decodeTxtRecordData(uint16_t txtLen, const unsigned char *txtRecord)
{
    std::vector<std::string> res;
    const unsigned char *cur = txtRecord;
    std::string::size_type i = 0;
    while (i < txtLen)
    {
        std::string::size_type len = static_cast<std::string::size_type>(*cur);
        if (len == 0)
            break;
        res.emplace_back(reinterpret_cast<const char*>(cur+1), len);
        cur += 1 + len;
        i += 1 + len;
    }
    return res;
}

std::string decodeDNSName(const std::string &str)
{
    std::string res;
    res.reserve(str.size()+2);
    for (std::string::const_iterator it = str.begin(), iend = str.end(); it != iend; ++it)
    {
        const char c = (*it);
        if (c == '\\')
        {
            if (++it == iend)
                break;
            const char c1 = *it;
            if (isdigit(c1))
            {
                if (++it == iend)
                    break;
                const char c2 = *it;
                if (isdigit(c2))
                {
                    if (++it == iend)
                        break;
                    const char c3 = *it;
                    if (isdigit(c3))
                    {
                        const char num[4] = {c1, c2, c3, '\0'};
                        res += static_cast<char>(atoi(num));
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
            else
            {
                res += c1;
            }
        }
        else
        {
            res += c;
        }
    }
    return res;
}

const char * getDnsSdErrorName(DNSServiceErrorType error)
{
    switch (error)
    {
        case kDNSServiceErr_NoError: return "kDNSServiceErr_NoError";
        case kDNSServiceErr_Unknown: return "kDNSServiceErr_Unknown";
        case kDNSServiceErr_NoSuchName: return "kDNSServiceErr_NoSuchName";
        case kDNSServiceErr_NoMemory: return "kDNSServiceErr_NoMemory";
        case kDNSServiceErr_BadParam: return "kDNSServiceErr_BadParam";
        case kDNSServiceErr_BadReference: return "kDNSServiceErr_BadReference";
        case kDNSServiceErr_BadState: return "kDNSServiceErr_BadState";
        case kDNSServiceErr_BadFlags: return "kDNSServiceErr_BadFlags";
        case kDNSServiceErr_Unsupported: return "kDNSServiceErr_Unsupported";
        case kDNSServiceErr_NotInitialized: return "kDNSServiceErr_NotInitialized";
        case kDNSServiceErr_AlreadyRegistered: return "kDNSServiceErr_AlreadyRegistered";
        case kDNSServiceErr_NameConflict: return "kDNSServiceErr_NameConflict";
        case kDNSServiceErr_Invalid: return "kDNSServiceErr_Invalid";
        case kDNSServiceErr_Firewall: return "kDNSServiceErr_Firewall";
        case kDNSServiceErr_Incompatible: return "kDNSServiceErr_Incompatible";
        case kDNSServiceErr_BadInterfaceIndex: return "kDNSServiceErr_BadInterfaceIndex";
        case kDNSServiceErr_Refused: return "kDNSServiceErr_Refused";
        case kDNSServiceErr_NoSuchRecord: return "kDNSServiceErr_NoSuchRecord";
        case kDNSServiceErr_NoAuth: return "kDNSServiceErr_NoAuth";
        case kDNSServiceErr_NoSuchKey: return "kDNSServiceErr_NoSuchKey";
        case kDNSServiceErr_NATTraversal: return "kDNSServiceErr_NATTraversal";
        case kDNSServiceErr_DoubleNAT: return "kDNSServiceErr_DoubleNAT";
        case kDNSServiceErr_BadTime: return "kDNSServiceErr_BadTime";
        default: return "Unknown";
    }
}

class DnsSdError: public std::runtime_error
{
public:

    DnsSdError(const std::string &message)
        : std::runtime_error(message)
    {
    }

    virtual ~DnsSdError() noexcept
    {
    }
};

} // unnamed namespace

class MDNSManager::PImpl
{
public:

    std::thread thread;
    ImplMutex mutex;
    std::atomic<bool> processEvents;
    DNSServiceRef connectionRef;

    struct RegisterRecord
    {
        DNSServiceRef serviceRef;
        MDNSService::Id serviceId;
        std::string serviceName;
        MDNSManager::PImpl &pimpl;

        RegisterRecord(const std::string &serviceName, MDNSManager::PImpl &pimpl)
            : serviceRef(0), serviceId(MDNSService::NO_SERVICE), serviceName(serviceName), pimpl(pimpl)
        { }

        /**
         * register callback
         */
        static void DNSSD_API registerCB(
            DNSServiceRef                       sdRef,
            DNSServiceFlags                     flags,
            DNSServiceErrorType                 errorCode,
            const char                          *name,
            const char                          *regtype,
            const char                          *domain,
            void                                *context )
        {
            // This is the asynchronous callback
            // Can be used to handle async. errors, get data from instantiated service or record references, etc.
            // Context is same pointer that was given to the callout
            // If registration was successful, errorCode = kDNSServiceErr_NoError
            RegisterRecord *self = static_cast<RegisterRecord*>(context);

            std::string serviceType = fromDnsSdStr(regtype);
            std::string serviceDomain = fromDnsSdStr(domain);

            // std::cerr << "REGISTER CALLBACK "<<name<<" EC "<<errorCode<<" FLAGS "<<flags<<" PTR "<<sdRef<<" self = "<<self<<std::endl;

            if (errorCode == kDNSServiceErr_NoError)
            {
                if (flags & kDNSServiceFlagsAdd)
                {
                    std::string newName = fromDnsSdStr(name);
                    if (self->serviceName != newName)
                    {
                        if (self->pimpl.alternativeServiceNameHandler)
                            self->pimpl.alternativeServiceNameHandler(newName, self->serviceName);
                    }
                }
                else
                {
                    removeTrailingDot(serviceType);
                    removeTrailingDot(serviceDomain);

                    self->pimpl.error(std::string("Could not register service '")+
                                      self->serviceName+"' (type: "+serviceType+", domain: "+serviceDomain+")");
                }
            }
            else
            {
                self->pimpl.error(std::string("Register callback: ")+getDnsSdErrorName(errorCode));
            }
        }

    };

    typedef std::unordered_map<MDNSService::Id, std::unique_ptr<RegisterRecord>> RegisterRecordMap;
    RegisterRecordMap registerRecordMap;

    struct BrowserRecord
    {
        MDNSServiceBrowser::Ptr handler;
        DNSServiceRef serviceRef;
        MDNSManager::PImpl &pimpl;

        BrowserRecord(const MDNSServiceBrowser::Ptr &handler, MDNSManager::PImpl &pimpl)
            : handler(handler), serviceRef(0), pimpl(pimpl)
        { }

        struct ResolveRecord
        {
            std::string type;
            std::string domain;
            BrowserRecord *parent;

            ResolveRecord(BrowserRecord *parent, std::string &&type, std::string &&domain)
                : type(std::move(type)), domain(std::move(domain)), parent(parent)
            {
            }
        };

        /**
         * browse callback
         */
        static void DNSSD_API browseCB(
                DNSServiceRef sdRef,
                DNSServiceFlags flags,
                uint32_t interfaceIndex,
                DNSServiceErrorType errorCode,
                const char *serviceName,
                const char *regtype,
                const char *replyDomain,
                void *context )
        {
            BrowserRecord *self = static_cast<BrowserRecord*>(context);

            std::string type = fromDnsSdStr(regtype);
            std::string domain = fromDnsSdStr(replyDomain);

            if (domain == ".")
            {
                // this browser response describes a service type

                if (self->handler)
                {
                    // remove trailing '.'
                    removeTrailingDot(type);

                    std::string::size_type i = type.find_last_of('.');
                    if (i != std::string::npos)
                    {
                        domain = type.substr(i+1);
                        type.resize(i);
                    }

                    type = fromDnsSdStr(serviceName)+"."+type;

                    if (flags & kDNSServiceFlagsAdd)
                    {
                        MDNSService service;
                        service.setInterfaceIndex(fromDnsSdInterfaceIndex(interfaceIndex));
                        service.setType(std::move(type));
                        service.setDomain(std::move(domain));

                        self->handler->onNewService(service);
                    }
                    else
                    {
                        self->handler->onRemovedService("", std::move(type), std::move(domain));
                    }
                }
            }
            else
            {
                // standard response
                if (flags & kDNSServiceFlagsAdd)
                {
                    std::unique_ptr<ResolveRecord> resrec(new ResolveRecord(self, std::move(type), std::move(domain)));
                    DNSServiceRef resolveRef = self->pimpl.connectionRef;
                    DNSServiceErrorType err =
                        DNSServiceResolve(&resolveRef,
                                          kDNSServiceFlagsShareConnection,
                                          interfaceIndex,
                                          serviceName,
                                          regtype,
                                          replyDomain,
                                          &resolveCB,
                                          resrec.get());

                    if (err == kDNSServiceErr_NoError)
                    {
                        resrec.release(); // resolveCB will delete ResolveRecord
                    }
                    else
                    {
                        self->pimpl.error(std::string("DNSServiceResolve: ")+getDnsSdErrorName(err));
                    }

                }
                else
                {
                    if (self->handler)
                    {
                        removeTrailingDot(type);
                        removeTrailingDot(domain);

                        self->handler->onRemovedService(serviceName, std::move(type), std::move(domain));
                    }
                }
            }
        }

        static void DNSSD_API resolveCB(DNSServiceRef sdRef,
                DNSServiceFlags flags,
                uint32_t interfaceIndex,
                DNSServiceErrorType errorCode,
                const char *fullname,
                const char *hosttarget,
                uint16_t port, /* In network byte order */
                uint16_t txtLen,
                const unsigned char *txtRecord,
                void *context )
        {
            ResolveRecord *rr = static_cast<ResolveRecord*>(context);
            BrowserRecord *self = static_cast<BrowserRecord*>(rr->parent);

            if (self->handler)
            {
                MDNSService service;
                service.setInterfaceIndex(fromDnsSdInterfaceIndex(interfaceIndex));

                std::string name = decodeDNSName(fromDnsSdStr(fullname));
                std::string suffix = std::string(".") + rr->type + rr->domain;
                std::string host = fromDnsSdStr(hosttarget);

                if (strEndsWith(name, suffix))
                {
                    name.resize(name.length()-suffix.length());
                }

                // remove trailing '.'
                removeTrailingDot(rr->type);
                removeTrailingDot(rr->domain);
                removeTrailingDot(host);

                service.setName(std::move(name));
                service.setType(std::move(rr->type));
                service.setDomain(std::move(rr->domain));
                service.setHost(std::move(host));
                service.setPort(port);
                service.setTxtRecords(decodeTxtRecordData(txtLen, txtRecord));

                self->handler->onNewService(service);
            }

            delete rr;

            DNSServiceRefDeallocate(sdRef);
        }

    };

    typedef std::unordered_multimap<MDNSServiceBrowser::Ptr, std::unique_ptr<BrowserRecord> > BrowserRecordMap;
    BrowserRecordMap browserRecordMap;

    MDNSManager::AlternativeServiceNameHandler alternativeServiceNameHandler;
    MDNSManager::ErrorHandler errorHandler;
    std::vector<std::string> errorLog;

    PImpl()
        : thread(), mutex(), processEvents(true), connectionRef(0)
    {
        DNSServiceErrorType errorCode = DNSServiceCreateConnection(&connectionRef);

        if (errorCode != kDNSServiceErr_NoError)
            throw DnsSdError(std::string("DNSServiceCreateConnection: ")+getDnsSdErrorName(errorCode));
    }

    ~PImpl()
    {
        stop();
        DNSServiceRefDeallocate(connectionRef);
    }

    void eventLoop()
    {
        int fd;

        {
            ImplLockGuard g(mutex);
            fd = DNSServiceRefSockFD(connectionRef);
        }

        if (fd == -1)
        {
            error("DNSServiceRefSockFD: failed");
            return;
        }

        int nfds = fd + 1;
        fd_set readfds;
        struct timeval tv;
        DNSServiceErrorType err;

        while (processEvents)
        {
            // 1. Set up the fd_set as usual here.
            FD_ZERO(&readfds);

            // 2. Add the fd to the fd_set
            FD_SET(fd, &readfds);

            // 3. Set up the timeout.
            tv.tv_sec = 1; // wakes up every 1 sec if no socket activity occurs
            tv.tv_usec = 0;

            // wait for pending data or timeout to elapse:
            int result = select(nfds, &readfds, (fd_set*) 0, (fd_set*) 0, &tv);
            if (result > 0)
            {
                {
                    ImplLockGuard g(mutex);
                    err = kDNSServiceErr_NoError;
                    if (FD_ISSET(fd, &readfds))
                        err = DNSServiceProcessResult(connectionRef);
                }
                if (err != kDNSServiceErr_NoError)
                    error(std::string("DNSServiceProcessResult returned ")+getDnsSdErrorName(err));
            }
            else if (result == 0)
            {
                // timeout elapsed but no fd-s were signalled.
            }
            else
            {
                error(std::string("select() returned ")+std::to_string(result)+" errno "+
                      std::to_string(errno)+" "+strerror(errno));
            }

            std::this_thread::yield();
        }
    }

    void run()
    {
        if (thread.joinable())
        {
            throw std::logic_error("MDNSManager already running");
        }
        processEvents = true;
        thread = std::move(std::thread(&PImpl::eventLoop, this));
    }

    void stop()
    {
        if (!thread.joinable())
        {
            throw std::logic_error("MDNSManager is not running");
        }
        processEvents = false;
        thread.join();
    }

    void error(std::string errorMsg)
    {
        ImplLockGuard g(mutex);

        if (errorHandler)
            errorHandler(errorMsg);
        errorLog.push_back(std::move(errorMsg));
    }

    void registerServiceBrowser(uint32_t interfaceIndex,
                                const char *dnsType,
                                const char *dnsDomain,
                                const MDNSServiceBrowser::Ptr & browser)
    {
        std::unique_ptr<BrowserRecord> brec(new BrowserRecord(browser, *this));

        brec->serviceRef = connectionRef;

        DNSServiceErrorType err =
            DNSServiceBrowse(&brec->serviceRef,
                             kDNSServiceFlagsShareConnection,
                             interfaceIndex,
                             dnsType,
                             dnsDomain,
                             &BrowserRecord::browseCB,
                             brec.get());

        if (err != kDNSServiceErr_NoError)
            throw DnsSdError(std::string("DNSServiceBrowse: ")+getDnsSdErrorName(err));

        browserRecordMap.insert(std::make_pair(brec->handler, std::move(brec)));
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
    ImplLockGuard g(pimpl_->mutex);
    pimpl_->alternativeServiceNameHandler = handler;
}

void MDNSManager::setErrorHandler(MDNSManager::ErrorHandler handler)
{
    ImplLockGuard g(pimpl_->mutex);
    pimpl_->errorHandler = handler;
}

void MDNSManager::registerService(MDNSService &service)
{
    if (service.getId() != MDNSService::NO_SERVICE)
        throw std::logic_error("Service was already registered");

    bool invalidFields;
    std::string txtRecordData = encodeTxtRecordData(service.getTxtRecords(), invalidFields);
    if (invalidFields)
    {
        throw DnsSdError("Invalid fields in TXT record of service '"+service.getName()+"'");
    }

    std::unique_ptr<MDNSManager::PImpl::RegisterRecord> rrec(
        new MDNSManager::PImpl::RegisterRecord(service.getName(), *pimpl_));

    std::string serviceType = service.getType();
    if (!serviceType.empty())
    {
        for (auto it = service.getSubtypes().begin(), eit = service.getSubtypes().end();
             it != eit; ++it)
        {
            serviceType += "," + *it;
        }
    }

    {
        ImplLockGuard g(pimpl_->mutex);

        DNSServiceRef sdRef = pimpl_->connectionRef;

        DNSServiceErrorType err =
            DNSServiceRegister(&sdRef,
                               kDNSServiceFlagsShareConnection,
                               toDnsSdInterfaceIndex(service.getInterfaceIndex()),
                               service.getName().c_str(),
                               toDnsSdStr(serviceType),
                               toDnsSdStr(service.getDomain()),
                               toDnsSdStr(service.getHost()),
                               service.getPort(),
                               static_cast<uint16_t>(txtRecordData.empty() ? 0 : txtRecordData.length()+1),
                               txtRecordData.empty() ? NULL : txtRecordData.c_str(),
                               &MDNSManager::PImpl::RegisterRecord::registerCB, // register callback
                               rrec.get());

        if (err != kDNSServiceErr_NoError)
            throw DnsSdError(std::string("DNSServiceRegister: ")+getDnsSdErrorName(err));

        rrec->serviceRef = sdRef;
        const MDNSService::Id serviceId = getNewServiceId();
        rrec->serviceId = serviceId;
        setServiceId(service, serviceId);
        pimpl_->registerRecordMap.insert(std::make_pair(serviceId, std::move(rrec)));
    }
}

void MDNSManager::unregisterService(MDNSService &service)
{
    ImplLockGuard g(pimpl_->mutex);
    if (service.getId() == MDNSService::NO_SERVICE)
        throw std::logic_error("Service was not registered");
    auto it = pimpl_->registerRecordMap.find(service.getId());
    if (it != pimpl_->registerRecordMap.end())
    {
        DNSServiceRefDeallocate(it->second->serviceRef);
        pimpl_->registerRecordMap.erase(it);
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

    {
        ImplLockGuard g(pimpl_->mutex);

        if (subtypes)
        {
            std::string subtype;
            for (auto it = subtypes->begin(), eit = subtypes->end(); it != eit; ++it)
            {
                subtype = type;
                if (!it->empty())
                    subtype += ("," + *it);
                pimpl_->registerServiceBrowser(toDnsSdInterfaceIndex(interfaceIndex),
                                               subtype.c_str(),
                                               toDnsSdStr(domain),
                                               browser);
            }
        }
        else
        {
            pimpl_->registerServiceBrowser(toDnsSdInterfaceIndex(interfaceIndex),
                                           type.c_str(),
                                           toDnsSdStr(domain),
                                           browser);
        }
    }
}

void MDNSManager::unregisterServiceBrowser(const MDNSServiceBrowser::Ptr & browser)
{
    ImplLockGuard g(pimpl_->mutex);
    auto range = pimpl_->browserRecordMap.equal_range(browser);
    for (auto it = range.first, eit = range.second; it != eit; ++it)
    {
        DNSServiceRefDeallocate(it->second->serviceRef);
    }
    pimpl_->browserRecordMap.erase(browser);
}

std::vector<std::string> MDNSManager::getErrorLog()
{
    std::vector<std::string> result;
    {
        ImplLockGuard g(pimpl_->mutex);
        result.swap(pimpl_->errorLog);
    }
    return result;
}

} // namespace MDNS
