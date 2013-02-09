package fuzzer;

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
	private String url;
	
	public WebPage(String url)
	{
		this.url = url;
	}
}
