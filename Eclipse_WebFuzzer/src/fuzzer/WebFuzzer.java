package fuzzer;

import java.net.URL;
import java.util.ArrayList;

/**
 * Web Fuzzer for team 'Denial of Service'
 * 
 * @author Eric Newman
 * @author Ross Kahn
 * @author Timothy Heard
 */
public class WebFuzzer
{
	private final URL rootURL;
	private ArrayList<URL> links;
	
	/**
	 * Default WebFuzzer constructor.
	 */
	public WebFuzzer(URL url)
	{
		rootURL = url;
		links = new ArrayList<URL>(); 
	}
}