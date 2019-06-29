# wfc-cert-tool module

For generating complete tree of certicates packed in jks files for A' and A+, based on a config. This is for non-PROD use only.
A sample config is in resources\cert_defs.conf.
To run it in IntelliJ IDEA, try the run configuration cert.

For creating CSRs for the nodes and/or networkmap and/or networkparameters in .p10 as well as the keys in JKS for both testing and PROD, based on a config.
A sample config is in resources\csr_defs.conf. The conf can have 0 or more nodes, 0 or 1 networkmap, 0 or 1 networkparameters.
To run it in IntelliJ IDEA, try the run configuration csr or csrOnNode

For creating JKS files for the trust root, networkmap, networkparameters, and the nodes.
To run it in IntelliJ IDEA, try the run configuration truststore, jks, or jksOnNode

To build,
./gradlew :experimental:wfc-cert-tool:clean :experimental:wfc-cert-tool:build -x test

Commands:
cert - generate a complete set of test certificates for a network based on a cert configuration file
csr - generate CSRs based on a csr configuration file
csrOnNode - generate CSRs for node based on node.conf and a csr configuration file, directly on the node
truststore - generate truststore.jks from rca.cer
jks - generate jks files for networkmap, networkparameters, node and ssl by packaging the private keys generated from csr and the certs from the issuing CAs
jksOnNode - generate jks files for node and ssl directly on the node into the certificates folder by packaging the private keys generated from csrOnNode and the certs from the issuing CAs

Options:
--config - file path to either the cert configuration or the csr configuration, required by cert, csr, csrOnNode, jks and jksOnNode
--csr - path to the csr folder, required by jks. jksOnNode uses base-directory/csr
--cer - path to the certs from the issuing CAs. It assumes a top level with rca.cer, ica1.cer and ica2.cer and subfolder cer with the certs for nodes and networkmap and networkparameters. Required by jks. jksOnNode uses base-directory/cer and base-directory/cer/cer.
--base-directory - path to the Corda node folder. Required by csrOnNode and jksOnNode.
--output - optional path for the output folder. It defaults to
certs subfolder of the folder containing the --config file for cert,
csrs subforlder of the folder containing the --config file for csr,
base-directory/csr for csrOnNode
base-directory/certificates for jksOnNode.
--keystore-pass - overrides the default password for store and key when jks and jksOnNode create node and ssl keystores.
--truststore-pass - overrides the default password for the trust store and key
--network-keystore-pass - overrides the default password for the networkmap and networkparameters store and key 


Some examples
To generate certs, without --output, it defaults to /Users/johnz/certs/wfc/sit/certs
java -jar certgen-5.0-SNAPSHOT.jar cert --config /Users/johnz/certs/wfc/sit/cert_defs.conf

To generate certs, with explicit --output
java -jar certgen-5.0-SNAPSHOT.jar cert --config /Users/johnz/certs/wfc/sit/cert_defs.conf --output /Users/johnz/certs/wfc/sit/test_certs

To generate CSRs, without --output, it defaults to /Users/johnz/certs/wfc/sit/csrs
java -jar certgen-5.0-SNAPSHOT.jar csr --config /Users/johnz/certs/wfc/sit/csr_defs.conf

To generate CSRs, with explicit --output
java -jar certgen-5.0-SNAPSHOT.jar csr --config /Users/johnz/certs/wfc/sit/csr_defs.conf --output /Users/johnz/certs/wfc/sit/test_csrs

To generate CSRs on the node
java -jar certgen-5.0-SNAPSHOT.jar csr csrOnNode --config /Users/johnz/certs/wfc/csr_defs.conf --base-directory /Users/johnz/certs/wfc/node_test

To generate the trust store, without --output, it defaults to /Users/johnz/certs/wfc/cer_test/truststore.jks
java -jar certgen-5.0-SNAPSHOT.jar truststore --cer /Users/johnz/certs/wfc/cer_test

To generate the trust store, with explicit --output
java -jar certgen-5.0-SNAPSHOT.jar truststore --cer /Users/johnz/certs/wfc/cer_test --output /Users/johnz/certs/wfc/cer_test_output

To generate JKS files for nodes and networkmap, networkparameters, without --output, it defaults to /Users/johnz/certs/wfc/cer_test
java -jar certgen-5.0-SNAPSHOT.jar jks --config /Users/johnz/certs/wfc/csr_defs.conf --csr /Users/johnz/certs/wfc/dev/csrs_20190622 --cer /Users/johnz/certs/wfc/cer_test

To generate JKS files for nodes and networkmap, networkparameters, without explicit --output
java -jar certgen-5.0-SNAPSHOT.jar jks --config /Users/johnz/certs/wfc/csr_defs.conf --csr /Users/johnz/certs/wfc/dev/csrs_20190622 --cer /Users/johnz/certs/wfc/cer_test --output /Users/johnz/certs/wfc/cer_test_output

To generate CSR on the node, the output will be in /Users/johnz/certs/wfc/node_test/csr
java -jar certgen-5.0-SNAPSHOT.jar csrOnNode --config /Users/johnz/certs/wfc/csr_defs.conf --base-directory /Users/johnz/certs/wfc/node_test

To generate JKS files on the node, it assumes the CSRs will be in /Users/johnz/certs/wfc/node_test/csr, and the issued certs will be in /Users/johnz/certs/wfc/node_test/cer. The output will be in /Users/johnz/certs/wfc/node_test/certificates.
java -jar certgen-5.0-SNAPSHOT.jar jksOnNode --config /Users/johnz/certs/wfc/csr_defs.conf --base-directory /Users/johnz/certs/wfc/node_test
