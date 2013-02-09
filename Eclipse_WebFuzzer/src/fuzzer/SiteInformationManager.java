package fuzzer;

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
	
	public SiteInformationManager(String url)
	{
		// TODO: Add any necessary error/exception checking (such as
		// for illegal/invalid URLs)
		this.baseUrl = getBaseUrl(url);
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
