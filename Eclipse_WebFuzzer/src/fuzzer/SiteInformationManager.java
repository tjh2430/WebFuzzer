package fuzzer;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;

/**
 * Provides a consolidated interface for accessing and managing vulnerability
 * and attack surface information for a specific web site (i.e. all of the
 * URLs/web pages which have the same base URL).
 * 
 * @author Eric Newman (edn6266)
 * @author Ross Kahn (rtk1865) 
 * @author Timothy Heard (tjh2430)
 */
public class SiteInformationManager
{
	private String baseUrl;
	private Map<String, WebPage> webPages;
	
	/**
	 * Private constructor for creating a SiteInformationManager for the site 
	 * at the given URL.  
	 */
	private SiteInformationManager(String url)
	{
		// TODO: Add any necessary error/exception checking (such as
		// for illegal/invalid URLs)
		this.baseUrl = getBaseUrl(url);
		this.webPages = new HashMap<String, WebPage>();
	}
	
	/**
	 * Attempts to find all possible inputs for given pageUrl as well as any 
	 * pages within the site (i.e. start with the same base URL) which are 
	 * linked to from that page's URL.
	 */
	public void performDiscoveryOnSite(String baseUrl)
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		performDiscoveryOnUrl(baseUrl, baseUrl);
	}
	
	// TODO: Add comment
	public void performDiscoveryOnUrl(String baseUrl, String pageUrl) 
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		WebPage webPage = WebPage.performDiscoveryOnPage(pageUrl);
		webPages.put(pageUrl, webPage);
		
		List<HtmlAnchor> links = webPage.getPage().getAnchors(); 
		for(HtmlAnchor link: links)
		{
			String linkUrl = webPage.getPage().getFullyQualifiedUrl(link.getHrefAttribute()).toString();
			if(webPages.containsKey(linkUrl) || !linkUrl.startsWith(baseUrl))
			{
				continue;
			}
						
			performDiscoveryOnUrl(baseUrl, linkUrl);			
		}
	}
	
	public Set<String> getSiteUrls()
	{
		return webPages.keySet();
	}
	
	public String getBaseUrl()
	{
		return baseUrl;
	}
	
	public WebPage getPage(String url)
	{
		return webPages.get(url);
	}
	
	// TODO: Add comment
	public static SiteInformationManager discoverAttackSurface(String baseUrl) 
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		SiteInformationManager informationManager = new SiteInformationManager(baseUrl);
		informationManager.performDiscoveryOnSite(baseUrl);		
		
		return informationManager;
	}

	// TODO: Remove this method from the WebFuzzer class (they are exact
	// copies of each other, and since its static it only needs to be in
	// one place anyways)
	public static String getBaseUrl(String url)
	{
		if(url == null || url.isEmpty())
		{
			return null;
		}
		
		int domainStart = url.indexOf("://");
		
		// If the pattern "://" cannot be found in the given URL string or if
		// that pattern only occurs at the end of the string then no base URL
		// can be extracted
		if(domainStart == -1 || (domainStart + 1) >= url.length())
		{
			return null;
		}		
		
		int baseUrlEnd = url.indexOf("/", (domainStart + 1));
		
		// If the given URL string does not contain any more forward slashes
		// after the initial two for "http://" or "https://" then the URL is
		// already in its base form
		if(baseUrlEnd == -1)
		{
			return url;
		}
		
		return url.substring(0, baseUrlEnd);
	}
}
