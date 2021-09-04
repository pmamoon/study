package io.security.corespringsecurity.security.factory;

import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.security.service.SecurityResourceService;

public class UrlResourcesMapFactoryBean implements FactoryBean <LinkedHashMap<RequestMatcher, List<ConfigAttribute>>>{

	private SecurityResourceService securityResourceService;
	
	private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;
	

	public UrlResourcesMapFactoryBean(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}

	@Override
	public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {
		
		if(resourceMap == null) {
			init();
		}
		
		return resourceMap;
	}
	
	private void init() {
		resourceMap = securityResourceService.getResourceList();
	}

	@Override
	public boolean isSingleton() {
		return true;
	}
	
	@Override
	public boolean equals(Object obj) {
		return super.equals(obj);
	}

	@Override
	public Class<?> getObjectType() {
		return LinkedHashMap.class;
	}
	
}
