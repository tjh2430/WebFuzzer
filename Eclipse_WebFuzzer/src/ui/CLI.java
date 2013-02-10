package ui;

import java.util.HashSet;
import java.util.InputMismatchException;
import java.util.Scanner;

import fuzzer.WebFuzzer;



public class CLI {

	private boolean startUp(){
		System.out.println("=========================");
		System.out.println("====== Web Fuzzer =======");
		System.out.println("=========================\n");
		
		System.out.println("What would you like to do?  :");
		System.out.println("\t1. Fuzz Web Page");
		System.out.println("\t2. Options");
		System.out.println("\t3. Exit");
		
		System.out.print(": ");
		
		Scanner scanner = new Scanner(System.in);
		try{
			int response = scanner.nextInt();
			
			switch(response){
			
			case 1:
				return fuzz();
			
			case 2: 
				return options();
				
			case 3:
				return false;
			}
			
			
		}catch(InputMismatchException ime){
			System.err.println("Error: please enter the number corresponding to the option");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		return true;
	}
	
	private boolean options(){
		System.out.println("\nSystem Options:");
		System.out.println("\t1. Set Time Gaps");
		System.out.println("\t2. Set Completeness");
		
		Scanner scanner = new Scanner(System.in);
		try{
			int response = scanner.nextInt();
			
			switch(response){
		
			case 1:
				return true;
				
			case 2:
				return true;
			}
	
		}catch(InputMismatchException ime){
			System.err.println("Error: please enter the number corresponding to the option");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		return true;
	}
	
	private boolean fuzz(){
		
		System.out.println("\n--- Fuzz a Web Page --- ");
		System.out.print("Enter a URL: ");
		
		Scanner scanner = new Scanner(System.in);
		try{
			String response = scanner.next();
			
			WebFuzzer.fuzz(WebFuzzer.getBaseUrl(response), response, new HashSet<String>());
			
		}catch(InputMismatchException ime){
			System.err.println("Error: please enter a valid URL");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Main method to run from command line.
	 */
	public static void main (String[] args)
	{
		/*if(args.length != 1)
		{
			System.out.println("Usage: java WebFuzzer <url>");
			return;
		}*/
		
		CLI cli = new CLI();
		
		boolean runFlag = true;
		while(runFlag){
			runFlag = cli.startUp();
		}
		
		
			
		/*try {
			String baseUrl = WebFuzzer.getBaseUrl(args[0]);
			WebFuzzer.fuzz(baseUrl, args[0], new HashSet<String>());			
		} catch (FailingHttpStatusCodeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		
		
	}
	
}
