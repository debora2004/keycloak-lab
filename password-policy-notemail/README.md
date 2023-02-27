# keycloak-custom-authenticator
Custom Authenticator implementation to be used as a reference. 

# Deployment
```shell script
mvn clean package
cp target/*.jar $KEYCLOAK_HOME/standalone/deployments/
```