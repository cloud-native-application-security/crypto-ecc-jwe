# crypto-key-exchange-dh-jwk

Demo project showing how to use **Elliptic Curve Diffie-Hellman (ECDH)** key exchange to generate 
a key for use with AES. Elliptic Curve 25519 is used for the key exchange, and the sample code
contains an example that uses the NIST P-256 curve. The keys are exchange using JSON Web Key (JWK).
There are three subprojects in this repo.

* utils - contains shared utility classes `CrptoUtils`,`JsonUtils` and `KeyExchange`.  
* warehouse - offers `/refunds` api that generates a JWE encrypted using a key derive via ECDH. 
  Depends on the utils project. 
* payments -  Makes an HTTP request to the warehouse `/refunds` endpoint to get the encrypted 
  refunds json. 

## Critical Warning

**DO NOT blindly copy/paste code from the samples into production applications**. 

The samples in this repo are for educational purposes to demonstrate security concepts in an easy
to understand way. NO effort has been put into making the code production ready. The key 
constraint for the code is that it can fit on a printed page and on slides. Therefore, we don't do 
validation in places where it should be done. We print secret keys to logs to explain the concepts.
We don't handle Java exceptions in a production worthy way. Furthermore, the samples typically 
explains one aspect of security and do the simplest thing to make the sample work, for example 
storing keys in plain text files, which is super insecure and should not be done in production.

Use this repo to learn security concepts so that you can better understand security protocols,
patterns and libraries. Once you learn the concepts it is your responsibility to implement those
concepts in a production quality, secure manner in your application. Please work with your 
information security team to determine the suitability of using the patterns shown in the 
samples to your specific situation.

## software prerequisites 

* Java 11 JDK 
* Java IDE 

## run on the command line

* run warehouse app `java -jar warehouse/target/warehouse-0.0.1-SNAPSHOT.jar` it will listen on 
  port `8082`. 
* run payments app `java -jar payments/target/payments-0.0.1-SNAPSHOT.jar` it will listen on port 
  `8081`.
* make an HTTP get request to `http://127.0.0.1:8081/` and you will get back JSON object.
* inspect the console output on the warehouse application nod you will an output showing the 
  value of the AES encryption key derived using ECDH. 
* inspect the console output of the payments application you will the AES key used for decryption 
  Notice it has the same value as the warehouse application. You will see the output of the
  response from the warehouse application containing the public key of the warehouse application, 
  and the encrypted JWE. If you scroll up in the console output you will see the actual HTTP 
  requests exchanged on the wire. 

## run from the IDE 

* run `com.example.warehouse.WarehouseApplication` it will listen on port `8082`. 
* run `com.example.payments.PaymentsApplication` it will listen on port `8081`. 
* Add a debugger breakpoint to the code in `com.example.warehouse.RefundController` 
* Add a debugger breakpoint to the code in `com.example.payments.PaymentsController`

## interesting files to look at 

* `util/src/main/java/com/example/util/KeyExchange.java` for the Diffie-Hellman key exchange
  implementation. 
* `util/src/main/java/com/example/util/CryptoUtils.java` to examine AES encryption
* `warehouse/src/main/java/com/example/warehouse/RefundController.java` to examine the code
that generates the api response from the warehouse app. 
* `payments/src/main/java/com/example/payments/PaymentsController.java` to examine the code 
  that calls the warehouse application api. 

