/**
  Custom JWT Auth Provider

  Implements direct use of JWTs as OAuth Bearer token for server-to-server integrations.

  Only supports Named Principal 

  Authors:  Chuck Mortimore
  Based on code by:  Jerry Huang & Bobby White
  Company:  Salesforce.com

**/
public class JWTAuthProvider extends Auth.AuthProviderPluginClass{

    public static final String RESOURCE_CALLBACK = '/services/authcallback/';
    public static final String DEFAULT_TOKEN_TYPE = 'Bearer';
    public static final String DUMMY_CODE = '999';

    // This class is dependant on this Custom Metadata Type created to hold custom parameters
    public static final String CUSTOM_MDT_NAME = 'JWT_Auth_Provider__mdt'; 
    public static final String CMT_FIELD_CALLBACK_URL = 'Callback_URL__c';
    public static final String CMT_FIELD_PROVIDER_NAME = 'Auth_Provider_Name__c';
    public static final String CMT_FIELD_CERTIFICATE_NAME = 'Certificate_Name__c';
    public static final String CMT_FIELD_ISSUER = 'Issuer__c';
    public static final String CMT_FIELD_AUDIENCE = 'Audience__c';

    /**
     Added Constructor purely for debugging purposes to have visibility as to when the class
     is being instantiated.
    **/
    public JWTAuthProvider() {
        super();
        System.debug('JWTAuthProvider Constructor called');
    }
    
    
    /**
        Name of custom metadata type to store this auth provider configuration fields
        This method is required by its abstract parent class.

    **/
    public String getCustomMetadataType() {
        return CUSTOM_MDT_NAME;
    } 
    
    /**
    Initiate callback. No End User authorization required in this flow so skip straight to the Token request.
    The interface requires the callback url to be defined. 
    Eg: https://test.salesforce.com/services/authcallback/<authprovidername>
    **/
    public PageReference initiate(Map<string,string> config, String stateToPropagate) {
        System.debug('JWTAuthProvider initiate');
        System.debug('-------config---------');
        System.debug(config);
        final PageReference pageRef = new PageReference(getCallbackUrl(config)); //NOSONAR
        pageRef.getParameters().put('state',stateToPropagate);
        pageRef.getParameters().put('code',DUMMY_CODE); // Empirically found this is required, but unused
        System.debug(pageRef.getUrl());
        return pageRef;
    } 

    /**
      This method composes the callback URL automatically UNLESS it has been overridden through Configuration.
      Normally one should not override the callback URL, but it's there in case the generated URL doesn't work.
    **/
    private String getCallbackUrl(Map<string,string> config) {
        // https://{salesforce-hostname}/services/authcallback/{urlsuffix}
        final String overrideUrl = config.get(CMT_FIELD_CALLBACK_URL);
        final String generatedUrl = URL.getSalesforceBaseUrl().toExternalForm() + RESOURCE_CALLBACK + config.get('Auth_Provider_Name__c');
        return String.isEmpty(overrideUrl) ? generatedUrl : overrideUrl;
    }
    
    /**
    Handle callback (from initial loop back "code" step in the flow).
    In the Client Credentials flow, this method retrieves the access token directly.

    Required by parent class.

    Error handling here is a bit painful as the UI never displays the exception or error message 
    supplied here.  The exception is thrown for Logging/Debugging purposes only. 
    **/
    public Auth.AuthProviderTokenResponse handleCallback(Map<string,string> config, Auth.AuthProviderCallbackState state ) {
        System.debug('JWTAuthProvider handleCallback');
        String jwt = generateToken(config);
        System.debug('Generated JWT: ' + jwt);
        return new Auth.AuthProviderTokenResponse(config.get(CMT_FIELD_PROVIDER_NAME)
                                                  , jwt
                                                  , generateRandomString()
                                                  , state.queryParameters.get('state'));
    } 
    
    /**
        Refresh is required by the parent class and it's used if the original Access Token has expired.
        In the Client Credentials flow, there is no Refresh token, so its implementation is exactly the
        same as the Initiate() step.
    **/
    public override Auth.OAuthRefreshResult refresh(Map<String,String> config, String refreshToken) {
        System.debug('JWTAuthProvider refresh');
        return new Auth.OAuthRefreshResult(generateToken(config), DEFAULT_TOKEN_TYPE);
    }

       
    /**
        getUserInfo is required by the Parent class, but not fully supported by this provider.
        Effectively the Client Credentials flow is only useful for Server-to-Server API integrations
        and cannot be used for other contexts such as a Registration Handler for Communities.
     **/
    public Auth.UserData getUserInfo(Map<string,string> config, Auth.AuthProviderTokenResponse response) {
        System.debug('JWTAuthProvider getUserInfo');
        final Auth.UserData userData = new Auth.UserData(
              getIdentity() // identifier
            , null // firstName
            , null // lastName
            , null // fullName
            , getIdentity() // email
            , null // link
            , getIdentity() // userName
            , null  //locale
            , config.get(CMT_FIELD_PROVIDER_NAME) //provider
            , null // siteLoginUrl
            , new Map<String,String>());
        return userData;
    }
    
    private String getIdentity() {
        return UserInfo.getUserName();
    }
    
    /**
       Private method that gets the Auth Token using the Client Credentials Flow.
    **/
     private String generateToken(Map<String,String> config) {
        System.debug('JWTAuthProvider generateToken');
        Auth.JWT jwt = new Auth.JWT();
        jwt.setSub(getIdentity()); 
        jwt.setAud(config.get(CMT_FIELD_AUDIENCE)); 
        jwt.setIss(config.get(CMT_FIELD_ISSUER));
        Auth.JWS jws = new Auth.JWS(jwt, config.get(CMT_FIELD_CERTIFICATE_NAME));
        System.debug('JWTAuthProvider returning compact serialization');
        return jws.getCompactSerialization();
    }
    
    private String generateRandomString() {
        final String chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz';
        String randStr = '';
        while (randStr.length() < 20) {
           Integer idx = Math.mod(Math.abs(Crypto.getRandomInteger()), chars.length());
           randStr += chars.substring(idx, idx+1);
        }
    return randStr; 
}
    
    
    /**
        Custom exception type so we can wrap and rethrow
    **/
    public class TokenException extends Exception {

    }
}