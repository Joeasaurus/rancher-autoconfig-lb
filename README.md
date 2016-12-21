# rancher-autoconfig-lb
Auto configure plugin for rancher load balancer to add SSL certs via LetsEncrypt and Route53!

Rancher Autoconfig LB
=====================

Launch this image with the following labels:

**Labels**

    io.rancher.container.create_agent: true
    io.rancher.container.agent.role: environment
    autoconfig.proxy.service_name: your-proxy-name


Service Labels
===============

If you want to add services with auto proxy configuration, add the following label:

**Labels**

    autoconfig.proxy.certificates: domain.tld:subdomain.domain.tld,other.domain.tld

If you want to add multiple certificates, use ';' as seperator.

The format of domain values see:

[SYNTAX OF THE COMBINATION OF ALL OPTIONAL FIELDS](http://docs.rancher.com/rancher/v1.1/zh/cattle/adding-load-balancers/#syntax-of-the-combination-of-all-optional-fields)
