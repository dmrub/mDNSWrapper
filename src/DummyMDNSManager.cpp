/*
 * DummyMDNSManager.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */
#include "MDNSManager.hpp"
#include <stdexcept>

namespace MDNS
{

class MDNSManager::PImpl { };

MDNSManager::MDNSManager()
    : pimpl_(static_cast<MDNSManager::PImpl*>(0))
{
    throw std::logic_error("No MDNS support available");
}

MDNSManager::~MDNSManager()
{
}

bool MDNSManager::isAvailable()
{
    return false;
}

void MDNSManager::run()
{
}

void MDNSManager::stop()
{
}

void MDNSManager::setAlternativeServiceNameHandler(MDNSManager::AlternativeServiceNameHandler handler)
{
}

void MDNSManager::setErrorHandler(MDNSManager::ErrorHandler handler)
{
}

void MDNSManager::registerService(MDNSService &service)
{

}

void MDNSManager::unregisterService(MDNSService &service)
{

}

void MDNSManager::registerServiceBrowser(MDNSInterfaceIndex interfaceIndex,
                                         const std::string &type,
                                         const std::vector<std::string> *subtypes,
                                         const std::string &domain,
                                         const MDNSServiceBrowser::Ptr & browser)
{
}

void MDNSManager::unregisterServiceBrowser(const MDNSServiceBrowser::Ptr & browser)
{
}

std::vector<std::string> MDNSManager::getErrorLog()
{
    std::vector<std::string> dummy;
    return dummy;
}

} // namespace MDNS
