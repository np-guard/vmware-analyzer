
Example test with following VMs example in namespace `foo`: 

```
$ kubectl get vms -n foo
NAME                     AGE   STATUS    READY
fedora-apricot-pike-81   73m   Running   True
fedora-tomato-zebra-41   78m   Running   True
```

Apply netpol `foo-default-deny.yaml` (blocks all traffic to/from VM `fedora-tomato-zebra-41`)

```
$ kubectl get netpol -A
NAMESPACE   NAME           POD-SELECTOR                                AGE
foo         default-deny   kubevirt.io/domain=fedora-tomato-zebra-41   30m
```

Get a `shell` for VM:

```
$ ./virtctl console fedora-tomato-zebra-41   -n foo
Successfully connected to fedora-tomato-zebra-41 console. The escape sequence is ^]

fedora-tomato-zebra-41 login: fedora
Password:
Last login: Mon Mar  3 07:07:57 on tty1


[fedora@fedora-tomato-zebra-41 ~]$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1360 qdisc fq_codel state UP group default qlen 1000
    link/ether 0a:58:c0:a8:00:03 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.3/24 brd 192.168.0.255 scope global dynamic noprefixroute enp1s0
       valid_lft 588sec preferred_lft 588sec
    inet6 fe80::858:c0ff:fea8:3/64 scope link noprefixroute
       valid_lft forever preferred_lft forever

[fedora@fedora-tomato-zebra-41 ~]$ ping 192.168.0.4
PING 192.168.0.4 (192.168.0.4) 56(84) bytes of data.



--- 192.168.0.4 ping statistics ---
7 packets transmitted, 0 received, 100% packet loss, time 6125ms


```

delete netpol `foo-default-deny.yaml`

```
$ kubectl delete netpol -n foo --all
$ kubectl get netpol -A
No resources found

```


now re-test ping 

```
[fedora@fedora-tomato-zebra-41 ~]$ ping 192.168.0.4
PING 192.168.0.4 (192.168.0.4) 56(84) bytes of data.
64 bytes from 192.168.0.4: icmp_seq=1 ttl=64 time=2.96 ms
64 bytes from 192.168.0.4: icmp_seq=2 ttl=64 time=2.04 ms
64 bytes from 192.168.0.4: icmp_seq=3 ttl=64 time=1.30 ms
```


apply policy:

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: foo
spec:
  podSelector:
    matchLabels:
      #app: fedora-tomato-zebra-41
      kubevirt.io/domain: fedora-tomato-zebra-41
  ingress:
  - ports:
    - port: 8080
  
  policyTypes:
  - Ingress
  - Egress
```

get shell to VM `apricot`

```

[fedora@fedora-apricot-pike-81 ~]$ curl 192.168.0.3
...
(no connection)

```

edit the policy to enable port `80` instead of `8080`:

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: foo
spec:
  podSelector:
    matchLabels:
      #app: fedora-tomato-zebra-41
      kubevirt.io/domain: fedora-tomato-zebra-41
  ingress:
  - ports:
    - port: 80
  
  policyTypes:
  - Ingress
  - Egress
```



test `curl` and `icmp`:

```

[fedora@fedora-apricot-pike-81 ~]$ curl 192.168.0.3
<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href=".bash_logout">.bash_logout</a></li>
<li><a href=".bash_profile">.bash_profile</a></li>
<li><a href=".bashrc">.bashrc</a></li>
<li><a href=".ssh/">.ssh/</a></li>
</ul>
<hr>
</body>
</html>
[fedora@fedora-apricot-pike-81 ~]$ ping 192.168.0.3
PING 192.168.0.3 (192.168.0.3) 56(84) bytes of data.




--- 192.168.0.3 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2068ms

[fedora@fedora-apricot-pike-81 ~]$
```


