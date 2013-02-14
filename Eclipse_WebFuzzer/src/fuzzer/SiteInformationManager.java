package fuzzer;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
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
	
	// TODO: Add sensitive data checks
	private List<String> vectors, sensitiveData, passwordDictionary, 
								sanitationInputs, pageGuesses;
	
	// TODO: Append reports of potential vulnerabilities at all steps of fuzzing
	// and discovery
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
	
	// TODO: Remove the baseUrl parameter given that this method is not static 
	// and therefore this method can directly access the baseUrl field
	private void performDiscoveryOnUrl(String baseUrl, String pageUrl) 
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		WebPage webPage = WebPage.performDiscoveryOnPage(pageUrl);
		webPages.put(pageUrl, webPage);
		
		// TODO: Check if the username will be null or simply empty if no username
		// is provided in the configurations
		if(webPage.requiresAuthentication() && configurations.getUsername() != null)
		{
			HtmlPage authenticationPage = null;

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
						// TODO: Make sure that this cast won't cause problems
						authenticationPage = (HtmlPage) webPage.attemptAuthentication(form, username, word);
						checkAuthenticationPage(authenticationPage, pageUrl, username, word);
					}
				}
			}
			else
			{
				password = configurations.getPassword();
				
				for(WebForm form: authenticationForms)
				{
					authenticationPage = (HtmlPage) webPage.attemptAuthentication(form, username, password);
					checkAuthenticationPage(authenticationPage, pageUrl, username, password);
				}
			}
		}
		
		performDiscoveryOnLinks(webPage, false);
	}
	
	/**
	 * Performs attack surface discovery on all the pages that are linked to from 
	 * the given web page which are a part of the same web site (i.e. start with the
	 * same base URL). If a value of true is passed into the logNewLinks parameter
	 * then any links which are found on this page which have not already been 
	 * encountered will be logged (this is used when following links from a unlinked
	 * page discovered through page guessing).   
	 */
	private void performDiscoveryOnLinks(WebPage webPage, boolean logNewLinks)
		throws FailingHttpStatusCodeException, IOException
	{
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
						
			if(logNewLinks)
			{
				vulnerabilityReport.append("New link found: " + linkUrl + "\n\n");
			}
			
			performDiscoveryOnUrl(baseUrl, linkUrl);			
		}
	}
	
	private void checkAuthenticationPage(HtmlPage authenticationPage, String pageUrl, String username, String password)
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		if(authenticationPage != null)// && --TODO: add check for authentication success string here--)
		{
			// Records that this was a successful combination
			vulnerabilityReport.append("On page at " + pageUrl +
					": successfully authenticated with username \"" + username + 
					"\" and password \"" + password + "\"\n\n");
			
			String authenticationPageUrl = authenticationPage.getUrl().toString();
			if(!webPages.containsKey(authenticationPageUrl))
			{
				WebPage discoveredPage = new WebPage(authenticationPage);
				webPages.put(authenticationPageUrl, discoveredPage);
				
				// Since the page reached after performing authentication has not
				// already been encountered, perform discovery from the page 
				List<HtmlAnchor> links = discoveredPage.getPage().getAnchors(); 
				for(HtmlAnchor link: links)
				{
					String linkUrl = discoveredPage.getPage().getFullyQualifiedUrl(link.getHrefAttribute()).toString();

					// If the page URL is not a part of the site being fuzzed of if this 
					// page URL has already been discovered then nothing needs to be done
					if(webPages.containsKey(linkUrl) || !linkUrl.startsWith(baseUrl))
					{
						continue;
					}
								
					performDiscoveryOnUrl(baseUrl, linkUrl);			
				}
			}
		}
		else
		{
			// Records that this was not a successful combination
			vulnerabilityReport.append("On page at " + pageUrl +
					": unable to authenticate with username \"" + username + 
					"\" and password \"" + password + "\"\n\n");
		}
	}
	
	private void performPageGuessing()
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
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
			
			// Checks to see if the current guess URL is actually a valid URL
			// and if so, the fact that an unlinked page was discovered for the
			// site is logged and then discovery is performed from this page 
			// (i.e. any links on the page are followed), logging any pages which can 
			// only be reached from this unlinked page (i.e. any previously 
			// undiscovered pages which are found by following links on the newly 
			// found page).
			if(urlExists(linkUrl))
			{
				vulnerabilityReport.append("Page guessing found an unlinked page at " +	linkUrl);
				
				WebPage webPage = WebPage.performDiscoveryOnPage(linkUrl);
				performDiscoveryOnLinks(webPage, true);
			}
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
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		loadConfigurations(configurationFileName);
		performDiscovery();
		performFuzzing();
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
				else if(nextToken.equals("authentication_success_string:"))
				{
					configurations.setAuthenticationSuccessString(tokenizer.nextToken());
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
						
						// TODO: Figure out how to verify whether or not there is a 
						// potential vulnerability
						
						// vulnerabilityReport.append("");
					}
					
					for(String inputToSanitize: sanitationInputs)
					{
						// Submit input and then check the url params to ensure
						// that the input has been changed
						input.type(inputToSanitize);
						
						// Submits the form
						resultingPage = submitField.click();
						
						// TODO: Check to see if the input was sanitized (changed)
						// at all
						
						// vulnerabilityReport.append("");
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
		// TODO: Add report header and the vulnerabilityReport contents
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
	
	/**
	 * Initializes and returns a new SiteInformationManager using the configurations contained in 
	 * the configuration file with the given file name after performing attack surface discovery
	 * and then fuzzing the discovered attack surface using the loaded configurations. 
	 */
	public static SiteInformationManager loadConfigurationAndFuzz(String configurationFileName)
		throws FailingHttpStatusCodeException, MalformedURLException, IOException
	{
		SiteInformationManager informationManager = new SiteInformationManager();
		informationManager.loadConfigurations(configurationFileName);
		informationManager.performDiscovery();
		informationManager.performFuzzing();
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
	
	/**
	 * Method for checking whether or not a given URL exists on the web.
	 * Taken from a response on stackoverflow 
	 * (http://stackoverflow.com/questions/4177864/checking-a-url-exist-or-not) 
	 */
	public static boolean urlExists(String url)
	{
	    try {
	      HttpURLConnection.setFollowRedirects(false);
	      // note : you may also need
	      //        HttpURLConnection.setInstanceFollowRedirects(false)
	      HttpURLConnection con =
	         (HttpURLConnection) new URL(url).openConnection();
	      con.setRequestMethod("HEAD");
	      return (con.getResponseCode() == HttpURLConnection.HTTP_OK);
	    }
	    catch (Exception e) {
	       return false;
	    }
	}
}
