/*
 * MDNSManager.hpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */

#ifndef MDNSMANAGER_HPP_INCLUDED
#define MDNSMANAGER_HPP_INCLUDED

#include <memory>
#include <functional>
#include <string>
#include <vector>
#include <utility>
#include <mutex>
#include <cstdint>

namespace MDNS
{

typedef uint32_t MDNSInterfaceIndex;
const MDNSInterfaceIndex MDNS_IF_ANY = 0; // use any interface for the service

class MDNSService;

class MDNSService
{
    friend class MDNSManager;
public:

    typedef unsigned int Id;
    static const Id NO_SERVICE = 0;

    MDNSService()
        : interfaceIndex_(MDNS_IF_ANY)
        , name_()
        , type_()
        , domain_()
        , host_()
        , port_()
        , txtRecords_()
        , subtypes_()
        , id_(NO_SERVICE)
    {
    }

    MDNSService(const std::string &name)
        : interfaceIndex_(MDNS_IF_ANY)
        , name_(name)
        , type_()
        , domain_()
        , host_()
        , port_()
        , txtRecords_()
        , subtypes_()
        , id_(NO_SERVICE)
    { }

    MDNSService(const MDNSService &other)
        : interfaceIndex_(other.interfaceIndex_)
        , name_(other.name_)
        , type_(other.type_)
        , domain_(other.domain_)
        , host_(other.host_)
        , port_(other.port_)
        , txtRecords_(other.txtRecords_)
        , subtypes_(other.subtypes_)
        , id_(other.id_)
    { }

    MDNSService(MDNSService &&other)
        : interfaceIndex_(other.interfaceIndex_)
        , name_(std::move(other.name_))
        , type_(std::move(other.type_))
        , domain_(std::move(other.domain_))
        , host_(std::move(other.host_))
        , port_(other.port_)
        , txtRecords_(std::move(other.txtRecords_))
        , subtypes_(std::move(other.subtypes_))
        , id_(other.id_)
    { }

    MDNSService & operator=(const MDNSService &other)
    {
        if (this != &other)
        {
            interfaceIndex_ = other.interfaceIndex_;
            name_ = other.name_;
            type_ = other.type_;
            domain_ = other.domain_;
            host_ = other.host_;
            port_ = other.port_;
            txtRecords_ = other.txtRecords_;
            subtypes_ = other.subtypes_;
            id_ = other.id_;
        }
        return *this;
    }

    MDNSService & operator=(MDNSService &&other)
    {
        if (this != &other)
        {
            interfaceIndex_ = other.interfaceIndex_;
            name_ = other.name_;
            type_ = other.type_;
            domain_ = other.domain_;
            host_ = other.host_;
            port_ = other.port_;
            txtRecords_ = other.txtRecords_;
            subtypes_ = other.subtypes_;
            id_ = other.id_;
        }
        return *this;
    }

    const std::string & getDomain() const
    {
        return domain_;
    }

    MDNSService & setDomain(const std::string & domain)
    {
        domain_ = domain;
        return *this;
    }

    MDNSService & setDomain(std::string && domain)
    {
        domain_ = std::move(domain);
        return *this;
    }

    const std::string & getHost() const
    {
        return host_;
    }

    MDNSService & setHost(const std::string & host)
    {
        host_ = host;
        return *this;
    }

    MDNSService & setHost(std::string && host)
    {
        host_ = std::move(host);
        return *this;
    }

    MDNSInterfaceIndex getInterfaceIndex() const
    {
        return interfaceIndex_;
    }

    void setInterfaceIndex(MDNSInterfaceIndex interfaceIndex)
    {
        interfaceIndex_ = interfaceIndex;
    }

    const std::string & getName() const
    {
        return name_;
    }

    MDNSService & setName(const std::string & name)
    {
        name_ = name;
        return *this;
    }

    MDNSService & setName(std::string && name)
    {
        name_ = std::move(name);
        return *this;
    }

    unsigned int getPort() const
    {
        return port_;
    }

    MDNSService & setPort(unsigned int port)
    {
        port_ = port;
        return *this;
    }

    const std::vector<std::string> & getSubtypes() const
    {
        return subtypes_;
    }

    MDNSService & setSubtypes(const std::vector<std::string> & subtypes)
    {
        subtypes_ = subtypes;
        return *this;
    }

    MDNSService & setSubtypes(std::vector<std::string> && subtypes)
    {
        subtypes_ = std::move(subtypes);
        return *this;
    }

    MDNSService & addSubtype(const std::string & subtype)
    {
        subtypes_.push_back(subtype);
        return *this;
    }

    MDNSService & addSubtype(std::string && subtype)
    {
        subtypes_.push_back(std::move(subtype));
        return *this;
    }

    const std::vector<std::string> & getTxtRecords() const
    {
        return txtRecords_;
    }

    MDNSService & setTxtRecords(const std::vector<std::string> & txtRecords)
    {
        txtRecords_ = txtRecords;
        return *this;
    }

    MDNSService & setTxtRecords(std::vector<std::string> && txtRecords)
    {
        txtRecords_ = std::move(txtRecords);
        return *this;
    }

    MDNSService & addTxtRecord(const std::string & txtRecord)
    {
        txtRecords_.push_back(txtRecord);
        return *this;
    }

    MDNSService & addTxtRecord(std::string && txtRecord)
    {
        txtRecords_.push_back(std::move(txtRecord));
        return *this;
    }

    const std::string & getType() const
    {
        return type_;
    }

    MDNSService & setType(const std::string & type)
    {
        type_ = type;
        return *this;
    }

    MDNSService & setType(std::string && type)
    {
        type_ = std::move(type);
        return *this;
    }

    Id getId() const
    {
        return id_;
    }

private:
    MDNSInterfaceIndex interfaceIndex_;   // index of the interface
    std::string name_;                    // name of the service
    std::string type_;                    // the service type followed by the protocol
    std::string domain_;                  // if not empty, specifies the domain on which to advertise the service
    std::string host_;                    // if not empty, specifies the SRV target host name.
    unsigned int port_;                   // the port, in network byte order, on which the service accepts connections.
    std::vector<std::string> txtRecords_; // TXT records
    std::vector<std::string> subtypes_;   // subtypes of the service
    Id id_;                               // registered service ID or NO_SERVICE
};

class MDNSServiceBrowser
{
public:

    typedef std::shared_ptr<MDNSServiceBrowser> Ptr;

    virtual void onNewService(const MDNSService &service) { }

    virtual void onRemovedService(const std::string &name, const std::string &type, const std::string &domain) { }

    virtual ~MDNSServiceBrowser() { }
};

class MDNSManager
{
public:

    typedef std::function<void (const std::string &newName, const std::string &oldName)> AlternativeServiceNameHandler;

    typedef std::function<void (const std::string &errorMsg)> ErrorHandler;

    MDNSManager();

    ~MDNSManager();

    void run();

    void stop();

    /**
     * Register handler for service name changes due to conflicts. Handler is executed in the event loop thread.
     */
    void setAlternativeServiceNameHandler(AlternativeServiceNameHandler handler);

    /**
     * Register handler for errors. Handler is executed in the event loop thread.
     */
    void setErrorHandler(ErrorHandler handler);

    void registerService(MDNSService &service);

    void unregisterService(MDNSService &service);

    /**
     * Register service browser for services on specified interface index,
     * service type, and domain.
     * Browser handler methods are called in event loop thread.
     */
    void registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                const std::string &type,
                                const std::string &domain,
                                const MDNSServiceBrowser::Ptr & browser)
    {
        // receive available service types when type is empty
        registerServiceBrowser(interfaceIndex,
                               type.empty() ? "_services._dns-sd._udp" : type,
                               static_cast<std::vector<std::string> *>(0),
                               domain,
                               browser);
    }

    /**
     * Register service browser for services on specified interface index,
     * service type, subtypes and domain.
     * Browser handler methods are called in event loop thread.
     */
    void registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                const std::string &type,
                                const std::vector<std::string> &subtypes,
                                const std::string &domain,
                                const MDNSServiceBrowser::Ptr & browser)
    {
        // receive available service types when type is empty
        registerServiceBrowser(interfaceIndex,
                               type.empty() ? "_services._dns-sd._udp" : type,
                               &subtypes,
                               domain,
                               browser);
    }

    /**
     * Unregister service
     */
    void unregisterServiceBrowser(const MDNSServiceBrowser::Ptr & browser);

    /**
     * Returns all error messages collected from last call to getErrorLog().
     */
    std::vector<std::string> getErrorLog();

    static bool isAvailable();

private:

    static MDNSService::Id getNewServiceId();

    static void setServiceId(MDNSService &service, MDNSService::Id id)
    {
        service.id_ = id;
    }

    void registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                const std::string &type,
                                const std::vector<std::string> *subtypes,
                                const std::string &domain,
                                const MDNSServiceBrowser::Ptr & browser);

    class PImpl;
    std::unique_ptr<PImpl> pimpl_;
};

} // namespace MDNS

#endif /* MDNSMANAGER_HPP_INCLUDED */
