package io.security.corespringsecurity.security.metadatasource;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.security.service.SecurityResourceService;

public class UrlFilterInvocationSecurityMetadatsSource implements FilterInvocationSecurityMetadataSource {

	private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();
	
	private SecurityResourceService securityResourceService;
	
	public UrlFilterInvocationSecurityMetadatsSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourcesMap, SecurityResourceService securityResourceService) {
		this.requestMap = resourcesMap;
		this.securityResourceService = securityResourceService;
		// TODO Auto-generated constructor stub
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		
		final HttpServletRequest request = ((FilterInvocation) object).getRequest();
		
		if(request != null) {
			for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
				RequestMatcher matcher = entry.getKey();
				System.out.println( " matcher >>  " + matcher + " request >> " + request.getRequestURI()
									+ " entry.getValue()  >>" + entry.getValue()+  " :: " + matcher.matches(request));
				if(matcher.matches(request)) {
					return entry.getValue();
				}
			}
		}
		return null;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> allAttribues = new HashSet<>();
		this.requestMap.values().forEach(allAttribues::addAll);
		return allAttribues ;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	public void reload() {
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();
		Iterator<Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();
		
		reloadedMap.clear();
		
		while (iterator.hasNext()) {
			Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
			requestMap.put(entry.getKey(), entry.getValue());
		}
	}
	

}
