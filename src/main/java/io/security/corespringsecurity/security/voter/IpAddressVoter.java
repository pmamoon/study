package io.security.corespringsecurity.security.voter;

import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import io.security.corespringsecurity.security.service.SecurityResourceService;

public class IpAddressVoter implements AccessDecisionVoter<Object> {

	private SecurityResourceService securityResourceService;
	
	public IpAddressVoter(SecurityResourceService securityResourceService) {
		// TODO Auto-generated constructor stub
		this.securityResourceService = securityResourceService;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}
	
	@Override
	public boolean supports(ConfigAttribute attribute) {
		return true;
	}
	
	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		
		WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
		String remoteAddress = details.getRemoteAddress();
		
		List<String> accessIpList = securityResourceService.getAccessIpList();
		
		int result = ACCESS_DENIED;
		
		for(String ipAddress : accessIpList) {
			if(remoteAddress.equals(ipAddress)) {
				return ACCESS_ABSTAIN;
			}
		}
		
		if(result == ACCESS_DENIED) {
			throw new AccessDeniedException("Invalid IpAddress");
		}
		
		return 0;
	}
}
