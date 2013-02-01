package fuzzer;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
/**
 * Web Fuzzer for team 'Denial of Service'
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
	
	/*
	 * Method to start crawling the page
	 */
	public static void fuzz(String url, Set<String> previousUrls) throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		WebClient client = new WebClient();
		HtmlPage page = client.getPage(url);
		DomNodeList<DomElement> inputs = page.getElementsByTagName("input");
		
		System.out.printf("\"%s\" Inputs:\n", url);
		for(DomElement e: inputs){
			System.out.println(e.asText());
		}
		
		// Print an extra new line to improve formatting
		System.out.println();
		
		List<HtmlAnchor> links = getLinks(url);
		for(HtmlAnchor link: links)
		{
			String linkUrl = page.getFullyQualifiedUrl(link.getHrefAttribute()).toString();
			if(previousUrls.contains(linkUrl))
			{
				continue;
			}
						
			previousUrls.add(linkUrl);
			fuzz(linkUrl, previousUrls);			
		}
	}
	
	public static List<HtmlAnchor> getLinks(String url) throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		WebClient client = new WebClient();
		HtmlPage page = client.getPage(url);
		
		return page.getAnchors();
	}
	
	/*
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
			fuzz(args[0], new HashSet<String>());			
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