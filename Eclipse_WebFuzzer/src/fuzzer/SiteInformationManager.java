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
import java.util.StringTokenizer;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

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
	public FuzzerData configurations;
	private List<String> vectors, sensitiveData, passwordDictionary, 
								sanitationInputs, pageGuesses;
	
	/*
	 * Used for logging potential vulnerabilities found by the fuzzer.
	 */
	private StringBuilder vulnerabilityReport;
	
	/**
	 * Private constructor for creating a SiteInformationManager for the site 
	 * at the given URL.  
	 */
	private SiteInformationManager()
	{
		this.webPages = new HashMap<String, WebPage>();
		this.vulnerabilityReport = new StringBuilder();
	}
	
	/**
	 * Initiate attack surface discovery using the currently loaded configurations.
	 * Attempts to find all possible inputs for every page on the site by following
	 * links to pages with the same base URL as well as attempting to access the 
	 * pages in the current pageGuesses list (taken from the configuration data 
	 * file). If any pages requiring authentication are encountered the set of 
	 * default login credentials provided in the configuration files will be used,
	 * unless password guessing is currently turned on, in which case the application
	 * will attempt to guess the password for the username provided in the 
	 * configuration file. If no username was provided in the configuration file or
	 * if a username was provided but no password was provided and password guessing
	 * is turned off then authentication will not be attempted and password fields
	 * will be treated the same as any other input.
	 */
	public void performDiscovery() 
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		// Note: It is important that page guessing be attempted after conventional
		// page discovery has been performed because otherwise the page guessing
		// method may inaccurately report that there are no links to a page when
		// in fact links do exist, they just haven't been explored yet.
		performDiscoveryOnUrl(baseUrl, baseUrl);
		performPageGuessing();
	}
	
	private void performDiscoveryOnUrl(String baseUrl, String pageUrl) 
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		WebPage webPage = WebPage.performDiscoveryOnPage(pageUrl);
		webPages.put(pageUrl, webPage);
		
		if(webPage.requiresAuthentication())
		{
			Page authenticationPage = null;

			List<WebForm> authenticationForms = webPage.getFormsWithAuthentication();
			String username = configurations.getUsername();
			String password; 
					
			if(configurations.passwordGuessingIsOn())
			{
				password = null;
				
				// TODO: Account for whether full or random completeness is on
				for(WebForm form: authenticationForms)
				{
					for(String word: passwordDictionary)
					{
						authenticationPage = webPage.attemptAuthentication(form, username, word);
						
						if(authenticationPage == null)
						{
							password = word;

							// TODO: Record that this was a successful combination and
							// keep track of all successful combinations
						}
					}
				}
			}
			else
			{
				password = configurations.getPassword();
				
				for(WebForm form: authenticationForms)
				{
					authenticationPage = webPage.attemptAuthentication(form, username, password);
					
					// TODO: Record that this was a successful combination
				}
			}
			
			if(authenticationPage == null)
			{
				// TODO: Figure out how to handle and log successfuly vs.
				// unsuccessful authentication
			}
			else
			{
				
			}
		}
		
		List<HtmlAnchor> links = webPage.getPage().getAnchors(); 
		for(HtmlAnchor link: links)
		{
			String linkUrl = webPage.getPage().getFullyQualifiedUrl(link.getHrefAttribute()).toString();

			// If the page URL is not a part of the site being fuzzed of if this 
			// page URL has already been discovered then nothing needs to be done
			if(webPages.containsKey(linkUrl) || !linkUrl.startsWith(baseUrl))
			{
				continue;
			}
						
			performDiscoveryOnUrl(baseUrl, linkUrl);			
		}
	}
	
	private void performPageGuessing()
	{
		for(String pageGuess: pageGuesses)
		{
			String linkUrl;
			
			if(baseUrl.endsWith("/"))
			{
				linkUrl = baseUrl + pageGuess;
			}
			else
			{
				linkUrl = baseUrl + "/" + pageGuess;
			}
			
			// If this page URL has already been discovered then nothing needs to
			// be done
			if(webPages.containsKey(linkUrl))
			{
				continue;
			}
			
			// TODO: Check if the current guess URL is actually a valid URL
			// and if so, log the fact that an unlinked page was discovered for the
			// site and then perform discovery (i.e. follow links) for this page,
			// logging any pages which can only be reached from this unlinked page
			// (i.e. any previously undiscovered pages which are found by following
			// links on the newly found page if possible).
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

	public void reconfigureRunAndReport(String configurationFileName)
	{
		// TODO: Implement as a one-shot method
	}
	
	/**
	 * Loads the configuration data contained in the configuration file with the given
	 * file name.
	 */
	public void loadConfigurations(String configurationFileName)
	{
		configurations = new FuzzerData();
		
		FileInputStream fstream;
		try 
		{
			fstream = new FileInputStream(configurationFileName);
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			
			StringTokenizer tokenizer;
			String line, nextToken;
			
			while((line = br.readLine()) != null){
				tokenizer = new StringTokenizer(line);
				
				nextToken = tokenizer.nextToken();
				
				if(nextToken.equals("app_data_file:"))
				{
					configurations.setDataFileName(tokenizer.nextToken());
				}
				else if(nextToken.equals("username:"))
				{
					configurations.setUsername(tokenizer.nextToken().replaceAll(" ", "\0"));
				}
				else if(nextToken.equals("password:"))
				{
					configurations.setPassword(tokenizer.nextToken().replaceAll(" ", "\0"));
				}
				else if(nextToken.equals("password_guessing:"))
				{
					String guessing = tokenizer.nextToken();
					if((guessing.equalsIgnoreCase("on")))
					{
						configurations.setPasswordGuessing(true);
					}
					else if((guessing.equalsIgnoreCase("off")))
					{
						configurations.setPasswordGuessing(false);
					}
				}
				else if(nextToken.equals("site_url:"))
				{
					baseUrl = tokenizer.nextToken();
				}
				else if(nextToken.equals("time_gap:"))
				{
					configurations.setTimeGap(Integer.parseInt(tokenizer.nextToken()));
				}
				else if(nextToken.equals("completeness:"))
				{
					String complete = tokenizer.nextToken();
					if((complete.equalsIgnoreCase("full")))
					{
						configurations.setCompleteness(true);
					}
					else if((complete.equalsIgnoreCase("random")))
					{
						configurations.setCompleteness(false);
					}
				}
			}
			
			br.close();
			
		} 
		catch (FileNotFoundException e) 
		{
			System.out.println("Configuration File Not Found");
			e.printStackTrace();
			return;
		}
		catch (IOException e) 
		{
			e.printStackTrace();
			return;
		}
		
		if(!configurations.getDataFileName().isEmpty())
		{
			loadData();
		}
	}
	
	/**
	 * Loads all the data from the data file into respective data structures.
	 */
	public void loadData()
	{
		vectors = new ArrayList<String>();
		sensitiveData = new ArrayList<String>();
		passwordDictionary = new ArrayList<String>();
		sanitationInputs = new ArrayList<String>();
		pageGuesses = new ArrayList<String>();
		
		FileInputStream fstream;
		try 
		{
			fstream = new FileInputStream(configurations.getDataFileName());
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			String line;
			
			while((line = br.readLine()) != null){
				if(line.equals("external fuzz vectors:"))
				{
					while((line = br.readLine()) != null)
					{
						vectors.add(line);
					}
				}
				else if(line.equals("sensitive data:"))
				{
					while((line = br.readLine()) != null)
					{
						sensitiveData.add(line);
					}
				}
				else if(line.equals("password dictionary:"))
				{
					while((line = br.readLine()) != null)
					{
						passwordDictionary.add(line);
					}
				}
				else if(line.equals("sanitization checking inputs:"))
				{
					while((line = br.readLine()) != null)
					{
						sanitationInputs.add(line);
					}
				}
				else if(line.equals("page guessing:"))
				{
					while((line = br.readLine()) != null)
					{
						pageGuesses.add(line);
					}
				}
			}
			
			br.close();
			
		} 
		catch (FileNotFoundException e) 
		{
			System.out.println("Data File Not Found");
			e.printStackTrace();
			return;
		}
		catch (IOException e) 
		{
			e.printStackTrace();
			return;
		}
	}
	
	// Check for lack of sanitization (different from fuzz vectors??)
	// Run external list of fuzz vectors
	public void runFuzzVectors()
		throws IOException
	{
		
		for(String pageName: webPages.keySet())
		{
			WebPage page = webPages.get(pageName);
			
			for(WebForm form: page.getForms())
			{
				HtmlSubmitInput submitField = form.getSubmitField();
				if(submitField == null)
				{
					// If the form cannot be submitted then nothing can be done
					// with this form
					break;
				}
				
				for(DomElement input: form.getInputs())
				{
					
					for(String vector: vectors)
					{
						//TODO: Bombard input! 
						
						// Submits the form
						submitField.click();
					}
				}
			}
		}
	}
	
	/**
	 * Performs fuzz testing on the currently discovered attack surface using 
	 * the currently loaded configurations and logs the results.
	 */
	public void performFuzzing()
		throws IOException
	{
		for(String pageName: webPages.keySet())
		{
			WebPage page = webPages.get(pageName);
			
			for(WebForm form: page.getForms())
			{
				HtmlSubmitInput submitField = form.getSubmitField();
				if(submitField == null)
				{
					// If the form cannot be submitted then nothing can be done
					// with this form
					break;
				}
				
				Page resultingPage;
				for(HtmlElement input: form.getInputs())
				{
					for(String vector: vectors)
					{
						input.type(vector);
						
						// Submits the form
						resultingPage = submitField.click();
					}
					
					// TODO: Run other inputs/checking (sensitive data, etc)
					for(String inputToSanitize: sanitationInputs)
					{
						// Submit input and then check the url params to ensure
						// that the input has been changed
						input.type(inputToSanitize);
						
						// Submits the form
						resultingPage = submitField.click();
						
						// TODO: Check to see if the input was sanitized (changed)
						// at all
					}
				}
			}
		}
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

	/**
	 * Initializes and returns a new SiteInformationManager using the configurations contained in 
	 * the configuration file with the given file name after performing attack surface discovery. 
	 */
	public static SiteInformationManager initSiteInformationManager(String configurationFileName)
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		SiteInformationManager informationManager = new SiteInformationManager();
		informationManager.loadConfigurations(configurationFileName);
		informationManager.performDiscovery();
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
