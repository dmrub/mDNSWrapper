/*
 * mdns-watch.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"
#include <iostream>
#include <unordered_set>
#include <unordered_map>

using namespace MDNS;

class MyBrowser: public MDNSServiceBrowser, public std::enable_shared_from_this<MyBrowser>
{
public:

    MyBrowser(MDNSManager &manager)
        : manager_(manager)
    { }

    void onNewService(const MDNSService &service) override
    {
        if (service.getName().empty())
        {
            auto it = serviceTypes_.find(service.getType());
            if (it == serviceTypes_.end())
            {
                std::cerr << "New service type '"<<service.getType() << "'" << std::endl;
                serviceTypes_.insert(service.getType());
                manager_.registerServiceBrowser(MDNS_IF_ANY, service.getType(), "", shared_from_this());
            }
        }
        else
        {
            std::cerr << "New service '"<<service.getName()<<"' of type '"<<service.getType()<<"' on domain "<<service.getDomain()
                      <<" (interface: "<<service.getInterfaceIndex()<<", host: "<<service.getHost()
                      <<", port "<<service.getPort()<<")"<<std::endl;
            if (!service.getTxtRecords().empty())
            {
                std::cerr << "  TXT ["<<std::endl;
                for (auto it = service.getTxtRecords().begin(), iend = service.getTxtRecords().end(); it != iend; ++it)
                {
                    std::cerr<<"    "<<*it<<std::endl;
                }
                std::cerr << "  ]"<<std::endl;
            }
        }
    }

    void onRemovedService(const std::string &name, const std::string &type, const std::string &domain, MDNSInterfaceIndex interfaceIndex) override
    {
        if (name.empty())
            std::cerr<<"Removed service type '"<<type<<"' on domain "<<domain<<" interface "<<interfaceIndex<<std::endl;
        else
            std::cerr<<"Removed service '"<<name<<"' of type '"<<type<<"' on domain "<<domain<<" interface "<<interfaceIndex<<std::endl;
    }

private:
    MDNSManager &manager_;
    std::unordered_set<std::string> serviceTypes_;
};

int main(int argc, char **argv)
{
    MDNSManager mgr;

    mgr.setAlternativeServiceNameHandler([](const std::string &newName, const std::string &oldName)
    {
        std::cerr<<"ALTERNATIVE SERVICE NAME "<<newName<<" FOR "<<oldName<<std::endl;
    });

    mgr.setErrorHandler([](const std::string &errorMsg)
    {
        std::cerr<<"ERROR "<<errorMsg<<std::endl;
    });

    MyBrowser::Ptr browser = std::make_shared<MyBrowser>(mgr);

    mgr.registerServiceBrowser(MDNS_IF_ANY, "", "", browser);

    std::cout << "Running loop. Press Enter to exit...";
    mgr.run();

    std::cin.get();

    std::cout<<"Exiting"<<std::endl;
}
