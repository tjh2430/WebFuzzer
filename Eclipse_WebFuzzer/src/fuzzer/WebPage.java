package fuzzer;

import java.io.IOException;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomAttr;
import com.gargoylesoftware.htmlunit.html.DomElement;
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
	private List<WebForm> webForms;
	private List<WebForm> formsWithAuthentication;
	private boolean authenticationRequired;
	
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
				
		this.webForms = WebForm.toWebForms(page.getElementsByTagName("form"));
		this.formsWithAuthentication = new ArrayList<WebForm>();
		
		// Authentication is considered to be required if any form on this web 
		// page contains at least one password input field.
		this.authenticationRequired = false;
		
		for(WebForm form: webForms)
		{
			if(form.requiresAuthentication())
			{
				this.authenticationRequired = true;
				formsWithAuthentication.add(form);
			}
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
	
	public List<WebForm> getForms()
	{
		return webForms;
	}
	
	public List<WebForm> getFormsWithAuthentication()
	{
		return formsWithAuthentication;
	}

	public boolean requiresAuthentication()
	{
		return authenticationRequired;
	}
	
	public Page attemptAuthentication(WebForm form, String username, String password)
	{
		// TODO: Implement => need to figure out how to determine whether or not
		// an authentication attempt was successful as well as how to get to the
		// authenticated version of the page/ the page past the login page 
		// programatically
		return null;
	}
	
	public void writeReport(PrintStream outputStream)
	{
		for(WebForm form: webForms)
		{
			DomAttr formAttrNode = form.getForm().getAttributeNode("id");
			
			if(formAttrNode == null)
			{
				outputStream.println("Outputs for an id-less form\n");
			}
			else
			{
				outputStream.println("form id: " + formAttrNode.getValue() + "\n");
			}
			
			for(DomElement e: form.getInputs())
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
