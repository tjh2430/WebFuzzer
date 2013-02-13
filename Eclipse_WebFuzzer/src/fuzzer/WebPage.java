package fuzzer;

import java.io.IOException;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomAttr;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.util.Cookie;

/**
 * Provides an interface for managing and interacting with vulnerability
 * information for a specific web page (i.e. a single URL).
 * 
 * @author Eric Newman (edn6266)
 * @author Ross Kahn (rtk1865) 
 * @author Timothy Heard (tjh2430)
 */
public class WebPage
{
	private WebClient client;
	private CookieManager cookieMgmt;
	private HtmlPage page;
	private URL url;
	private Map<DomElement, DomNodeList<HtmlElement>> formInputs;
	
	/**
	 * Private constructor for creating a WebPage for the page at the given URL. 
	 */
	private WebPage(String pageUrl) 
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		this.client = new WebClient();
		this.cookieMgmt = client.getCookieManager();
		this.page = client.getPage(pageUrl);
		this.url = new URL(pageUrl);
		
		formInputs = new HashMap<DomElement, DomNodeList<HtmlElement>>();
		DomNodeList<DomElement> forms = page.getElementsByTagName("form");
		
		for(DomElement form: forms)
		{
			formInputs.put(form, form.getElementsByTagName("input"));
		}
	}
	
	public WebClient getClient()
	{
		return client;
	}

	public CookieManager getCookieMgmt()
	{
		return cookieMgmt;
	}

	public HtmlPage getPage()
	{
		return page;
	}
	
	public URL getUrl()
	{
		return url;
	}
	
	public Set<DomElement> getForms()
	{
		return formInputs.keySet();
	}

	public void writeReport(PrintStream outputStream)
	{
		for(DomElement form: formInputs.keySet())
		{
			DomAttr formAttrNode = form.getAttributeNode("id");
			
			if(formAttrNode == null)
			{
				outputStream.println("Outputs for an id-less form\n");
			}
			else
			{
				outputStream.println("form id: " + formAttrNode.getValue() + "\n");
			}
			
			for(DomElement e: form.getElementsByTagName("input"))
			{
				DomAttr attrNode = e.getAttributeNode("id");
				
				if(attrNode == null)
				{
					outputStream.println("id-less input: " + e.asXml());
				}
				else
				{
					outputStream.println("input id: " + attrNode.getValue() + " => " + e.asXml());
				}
			}
		}
		
		// New line for formatting
		outputStream.println("");
		
		//Prints Query parameter in URL
		outputStream.println("Url Query: " + url.getQuery() + "\n");
		
		Set<Cookie> cookies = cookieMgmt.getCookies();
		for(Cookie c: cookies)
		{
			outputStream.println(c.toString());
		}		
	}

	public static WebPage performDiscoveryOnPage(String url) 
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		WebPage webPage = new WebPage(url);
		return webPage;
	}
}
