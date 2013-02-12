package fuzzer;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.util.ArrayList;
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
	private FuzzerData configurations;
	
	/**
	 * Private constructor for creating a SiteInformationManager for the site 
	 * at the given URL.  
	 */
	private SiteInformationManager(String url, FuzzerData configurationData)
	{
		// TODO: Add any necessary error/exception checking (such as
		// for illegal/invalid URLs)
		this.baseUrl = getBaseUrl(url);
		this.webPages = new HashMap<String, WebPage>();
		
		// TODO: Make use of the configurationData parameter
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
	
	// Specify time gap (what exactly does this mean?)
	// Specify completeness option
	// Turn password guesses on or off??
	public void configure(FuzzerData configurationData)
	{
		this.configurations = configurationData;
	}
	
	// Check for lack of sanitization (different from fuzz vectors??)
	// Run external list of fuzz vectors
	public void runFuzzVectors(String fuzzVectorFileName)
	{
		List<String> vectors = new ArrayList<String>();
		
		FileInputStream fstream;
		try 
		{
			fstream = new FileInputStream(fuzzVectorFileName);
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			String line;
			
			while((line = br.readLine()) != null){
				vectors.add(line);
			}
			
			br.close();
			
		} 
		catch (FileNotFoundException e) 
		{
			System.out.println("Fuzz Vector File Not Found");
			e.printStackTrace();
			return;
		}
		catch (IOException e) 
		{
			e.printStackTrace();
			return;
		}
		
		//for(/*TODO: Iterate through inputs*/)
		//{
			for(String vector: vectors)
			{
				//TODO: Bombard input! 
			}
		//}
	}
	
	// TODO: Implement checks on all responses received
	// Sensitive data??? ("mysql", stack-traces, raw exceptions, etc.)
	//
	
	// Password authentication
	// -> Allow user to specify a username and password as well as which
	//    input fields they should be sent to
	/**
	 * 
	 * @param webPage
	 * @param formId
	 * @param inputIdsToValues	A mapping of input tag ids to the input values to put into them
	 */
	public void submitInputs(WebPage webPage, String formId, Map<String, String> inputIdsToValues)
	{
		// TODO: Implement
	}
	
	/**
	 * Writes a detailed report on the vulnerability and attack surface 
	 * information which has been discovered for the site being examined.
	 *
	 * @param outputStream	The PrintStream to write the report to
	 */
	public void writeReport(PrintStream outputStream)
	{
		// TODO: Add report header
		outputStream.println("------------------------------------------------------------------------------");
		outputStream.println("Report for site based at " + baseUrl + "\n");
		
		
		for(String url: webPages.keySet())
		{
			outputStream.println("------------------------------------------------------------------------------");
			outputStream.println("Page: " + url + "\n");
			webPages.get(url).writeReport(outputStream);
		}
		
		outputStream.println("------------------------------------------------------------------------------");
	}
	
	// TODO: Add comment
	public static SiteInformationManager discoverAttackSurface(String baseUrl, FuzzerData configurationData) 
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		SiteInformationManager informationManager = new SiteInformationManager(baseUrl, configurationData);
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
