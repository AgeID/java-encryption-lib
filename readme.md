
**AgeId Encryption Helper**

AES256 encryption and decryption helper for AgeID using an embedded random salt key.

  

**Requirements**:

* jdk ^1.5

* maven ^2

  

**If jdk less then 1.8:**

Download Java Cryptography Extension (JCE), from the official Oracle site, for the appropriate jre version
and replace the files {JAVA_HOME}\lib\security\local_policy.jar and {JAVA_HOME}\lib\security\US_export_policy.jar with the ones downloaded.

  

## Commands

* clone projet:

```console

git clone https://github.com/AgeID/java-encryption-lib.git

```

* install dependencies:

```console

mvn clean install

```

* build project:

```console

mvn build

```

* test:

```console

mvn test

```
