/*
 * testclient.cpp
 *
 *  Created on: Jan 12, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"
#include <iostream>

using namespace MDNS;

class MyBrowser: public MDNSServiceBrowser
{
public:

    MyBrowser(const std::string &name)
        : name_(name)
    { }

    void onNewService(const MDNSService &service) override
    {
        std::cerr << "New "<<name_<<" service "<<service.getName()<<" of type "<<service.getType()<<" on domain "<<service.getDomain()
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

    void onRemovedService(const std::string &name, const std::string &type, const std::string &domain) override
    {
        std::cerr<<"Removed "<<name_<<" service "<<name<<" of type "<<type<<" on domain "<<domain<<std::endl;
    }

private:
    std::string name_;
};

int main(int argc, char **argv)
{
    MDNSManager mgr;

    MDNSService s1, s2;

    mgr.setAlternativeServiceNameHandler([](const std::string &newName, const std::string &oldName)
    {
        std::cerr<<"ALTERNATIVE SERVICE NAME "<<newName<<" FOR "<<oldName<<std::endl;
    });

    mgr.setErrorHandler([](const std::string &errorMsg)
    {
        std::cerr<<"ERROR "<<errorMsg<<std::endl;
    });

    MyBrowser::Ptr httpBrowser = std::make_shared<MyBrowser>("HTTP");
    MyBrowser::Ptr arvidaBrowser = std::make_shared<MyBrowser>("ARVIDA");
    MyBrowser::Ptr allBrowser = std::make_shared<MyBrowser>("ALL");

    mgr.registerServiceBrowser(MDNS_IF_ANY, "_http._tcp", "", httpBrowser);
    mgr.registerServiceBrowser(MDNS_IF_ANY, "_http._tcp", {"_arvida"}, "", arvidaBrowser);
    //mgr.registerServiceBrowser(MDNS_IF_ANY, "", "", allBrowser);

    s1.setName("MyService").setPort(8080).setType("_http._tcp").addTxtRecord("path=/foobar");
    mgr.registerService(s1);

    std::cout << "Running loop...";
    mgr.run();

    s2.setName("ARVIDA Service").setPort(9090).setType("_http._tcp").addSubtype("_arvida").addTxtRecord("FOO=BOO");
    mgr.registerService(s2);

    std::cin.get();

    std::cout<<"Unregister services..."<<std::endl;

    mgr.unregisterService(s1);
    mgr.unregisterService(s2);

    std::cout<<"Exiting"<<std::endl;

    std::cin.get();
}
