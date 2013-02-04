package fuzzer;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomAttr;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.util.Cookie;

/**
 * Web Fuzzer for team 'Denial of Service'.
 * 
 * @author Eric Newman
 * @author Ross Kahn
 * @author Timothy Heard
 */
public class WebFuzzer
{
	
	/**
	 * Default WebFuzzer constructor.
	 */
	public WebFuzzer( URL url )
	{
		
	}
	
	/**
	 * Attempts to find all possible inputs for given pageUrl as well as any 
	 * pages within the site (i.e. start with the same base URL) which are 
	 * linked to from that page's URL.
	 */
	public static void fuzz(String baseUrl, String pageUrl, Set<String> previousUrls)
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		WebClient client = new WebClient();
		CookieManager cookieMgmt = client.getCookieManager();
		HtmlPage page = client.getPage(pageUrl);
		DomNodeList<DomElement> inputs = page.getElementsByTagName("input");
		
		System.out.printf("\"%s\" Inputs:\n\n", pageUrl);
		for(DomElement e: inputs){
			DomAttr attrNode = e.getAttributeNode("id");
			
			if(attrNode == null)
			{
				System.out.println("id-less input: " + e.asXml());
			}
			else
			{
				System.out.println("input id: " + attrNode.getValue() + " => " + e.asXml());
			}
		}
		
		// Print an extra new line to improve formatting
		System.out.println();

		System.out.println("Cookies:");
		
		Set<Cookie> cookies = cookieMgmt.getCookies();
		
		for(Cookie c: cookies)
		{
			System.out.println(c.toString());
		}
		
		// Print an extra new line to improve formatting
		System.out.println();
		
		List<HtmlAnchor> links = getLinks(pageUrl);
		for(HtmlAnchor link: links)
		{
			String linkUrl = page.getFullyQualifiedUrl(link.getHrefAttribute()).toString();
			if(previousUrls.contains(linkUrl) || !linkUrl.startsWith(baseUrl))
			{
				continue;
			}
						
			previousUrls.add(linkUrl);
			fuzz(baseUrl, linkUrl, previousUrls);			
		}
	}
	
	public static List<HtmlAnchor> getLinks(String url)
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		WebClient client = new WebClient();
		HtmlPage page = client.getPage(url);
		
		return page.getAnchors();
	}

	private static String getBaseUrl(String url)
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
	
	/**
	 * Main method to run from command line.
	 */
	public static void main (String[] args)
	{
		if(args.length != 1)
		{
			System.out.println("Usage: java WebFuzzer <url>");
			return;
		}
		
		try {
			String baseUrl = getBaseUrl(args[0]);
			fuzz(baseUrl, args[0], new HashSet<String>());			
		} catch (FailingHttpStatusCodeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
}