# wfc-cert-tool module

For generating complete tree of certicates packed in jks files for A' and A+, based on a config. This is for non-PROD use only.
A sample config is in resources\cert_defs.conf.
To run it in IntelliJ IDEA, try the run configuration cert.

For creating CSRs for the nodes and/or networkmap and/or networkparameters in .p10 as well as the keys in JKS for both testing and PROD, based on a config.
A sample config is in resources\csr_defs.conf. The conf can have 0 or more nodes, 0 or 1 networkmap, 0 or 1 networkparameters.
To run it in IntelliJ IDEA, try the run configuration csr.

To build,
./gradlew :experimental:wfc-cert-tool:clean :experimental:wfc-cert-tool:build -x test

Then, use the examples below.
To generate certs, without --output, it defaults to /Users/johnz/certs/wfc/sit/certs
java -jar certgen-5.0-SNAPSHOT.jar cert --config /Users/johnz/certs/wfc/sit/cert_defs.conf

To generate certs, with explicit --output
java -jar certgen-5.0-SNAPSHOT.jar cert --config /Users/johnz/certs/wfc/sit/cert_defs.conf --output /Users/johnz/certs/wfc/sit/test_certs


To create CSRs, without --output, it defaults to /Users/johnz/certs/wfc/sit/csrs
java -jar certgen-5.0-SNAPSHOT.jar csr --config /Users/johnz/certs/wfc/sit/csr_defs.conf

To generate certs, with explicit --output
java -jar certgen-5.0-SNAPSHOT.jar csr --config /Users/johnz/certs/wfc/sit/csr_defs.conf --output /Users/johnz/certs/wfc/sit/test_csrs
