package app.permissionizer.server.util;

import app.permissionizer.server.PermissionizerProperties;
import app.permissionizer.server.exception.TokenValidationException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.text.ParseException;

@Component
public class IdTokenValidator {

    private final PermissionizerProperties properties;

    public IdTokenValidator(PermissionizerProperties properties) {
        this.properties = properties;
    }

    public IDTokenClaimsSet validateIdToken(String idToken) {
        try {
            OIDCClientMetadata metadata = new OIDCClientMetadata();
            metadata.setIDTokenJWSAlg(JWSAlgorithm.RS256);
            Issuer issuer = new Issuer("https://token.actions.githubusercontent.com");
            OIDCClientInformation clientInformation = new OIDCClientInformation(
                    new ClientID(properties.expectedAudience()), null, metadata, null);

            OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.resolve(issuer);
            IDTokenValidator idTokenValidator = IDTokenValidator.create(providerMetadata, clientInformation);

            return idTokenValidator.validate(SignedJWT.parse(idToken), null);
        } catch (GeneralException | IOException | ParseException | JOSEException | BadJOSEException e) {
            throw new TokenValidationException("Failed to validate incoming ID Token: " + e.getMessage(), e);
        }
    }
}
