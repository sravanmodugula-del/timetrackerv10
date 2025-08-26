import { Strategy as SamlStrategy } from 'passport-saml';
import type { Profile } from 'passport-saml';
import { upsertUser, getUserByEmail } from '../storage';

export interface SAMLProfile extends Profile {
  email?: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  nameID?: string;
  nameIDFormat?: string;
  sessionIndex?: string;
  role?: string;
  department?: string;
}

// Role mapping from SAML attributes to application roles
const mapSamlRoleToAppRole = (samlRole?: string): string => {
  if (!samlRole) return 'employee';

  const roleMappings: Record<string, string> = {
    'TimeTracker-Admins': 'admin',
    'TimeTracker-Managers': 'manager',
    'TimeTracker-ProjectManagers': 'project_manager',
    'TimeTracker-Employees': 'employee',
    'TimeTracker-Viewers': 'viewer',
    // Add more role mappings as needed
    'admin': 'admin',
    'manager': 'manager',
    'project_manager': 'project_manager',
    'employee': 'employee',
    'viewer': 'viewer'
  };

  return roleMappings[samlRole.toLowerCase()] || 'employee';
};

export const createSamlStrategy = () => {
  if (!process.env.SAML_ENABLED || process.env.SAML_ENABLED !== 'true') {
    return null;
  }

  // Use hardcoded values for TimeTracker FMB configuration
  const samlConfig = {
    entryPoint: process.env.SAML_ENTRY_POINT || 'https://timetracker.fmb.com/saml/sso',
    issuer: 'a0tt0vrnu3tt',
    callbackUrl: 'https://timetracker.fmb.com/saml/acs',
    audience: 'https://timetracker.fmb.com/saml/metadata',
  };

  // Check if certificate is provided and not a placeholder
  const cert = process.env.SAML_CERT;
  if (!cert || cert.includes('PLACEHOLDER') || cert.trim() === '') {
    console.warn('⚠️ SAML certificate not configured properly. Using development mode.');
    // For development, you might want to disable certificate validation
    // In production, this should throw an error
    if (process.env.NODE_ENV === 'production') {
      throw new Error('SAML certificate is required in production mode');
    }
  }

  const options: SamlConfig = {
    entryPoint: samlConfig.entryPoint,
    issuer: samlConfig.issuer,
    callbackUrl: samlConfig.callbackUrl,
    audience: samlConfig.audience,
    cert: cert && !cert.includes('PLACEHOLDER') ? cert : 'dummy-cert-for-dev',
    privateKey: process.env.SAML_PRIVATE_KEY && !process.env.SAML_PRIVATE_KEY.includes('PLACEHOLDER') ? process.env.SAML_PRIVATE_KEY : undefined,
    identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
    acceptedClockSkewMs: 60000, // 1 minute clock skew tolerance
    disableRequestedAuthnContext: true, // Disable authn context to be more flexible
    wantAssertionsSigned: process.env.NODE_ENV === 'production',
    wantAuthnResponseSigned: process.env.NODE_ENV === 'production',
    signatureAlgorithm: 'sha256',
    digestAlgorithm: 'sha256',
  };

  return new SamlStrategy(
    options,
    async (profile: SAMLProfile, done) => {
      try {
        console.log('🔐 SAML Profile received:', JSON.stringify(profile, null, 2));

        // Extract user information from SAML profile
        // Try multiple ways to get the email since different IdPs structure this differently
        const email = profile.email || profile.nameID || profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];
        const firstName = profile.firstName || profile.givenName || profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'] || profile.displayName?.split(' ')[0] || '';
        const lastName = profile.lastName || profile.surname || profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'] || profile.displayName?.split(' ').slice(1).join(' ') || '';
        const samlRole = profile.role || profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'] || 'employee';
        const appRole = mapSamlRoleToAppRole(samlRole);

        console.log('🔍 SAML NameID:', profile.nameID);
        console.log('🔍 SAML NameIDFormat:', profile.nameIDFormat);
        console.log('🔍 Extracted email:', email);

        if (!email) {
          console.error('❌ No email found in SAML profile. Available attributes:', Object.keys(profile));
          return done(new Error('Email is required from SAML provider'), null);
        }

        // Upsert user in database
        await upsertUser({
          id: profile.nameID || email,
          email: email,
          firstName: firstName,
          lastName: lastName,
          profileImageUrl: null,
        });

        // Note: updateUserRole function doesn't exist in storage.ts
        // You'll need to implement role management separately or update the user with role

        // Create user object for session
        const user = {
          claims: {
            sub: profile.nameID || email,
            email: email,
            first_name: firstName,
            last_name: lastName
          },
          samlProfile: profile,
          authSource: 'saml'
        };

        console.log('✅ SAML user authenticated successfully:', email, 'Role:', appRole);
        return done(null, user);

      } catch (error) {
        console.error('❌ SAML authentication error:', error);
        return done(error, null);
      }
    }
  );
};

export const generateSamlMetadata = () => {
  const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="a0tt0vrnu3tt">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="https://timetracker.fmb.com/saml/acs"
                                 index="1" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>`;

  return metadata;
};