package ui;

import java.util.HashSet;
import java.util.InputMismatchException;
import java.util.Scanner;

import fuzzer.FuzzerData;
import fuzzer.WebFuzzer;



public class CLI {
	
	private static final boolean RUN = true;
	private static final boolean EXIT = false;

	private boolean startUp(){
		System.out.println("=========================");
		System.out.println("====== Web Fuzzer =======");
		System.out.println("=========================\n");
		
		System.out.println("What would you like to do?  :");
		System.out.println("\t1. Fuzz Web Page");
		System.out.println("\t2. Options");
		System.out.println("\t3. Exit");
		
		System.out.print(": ");
		
		int response = getMenuSelection();
		
		switch(response){
		
		case -1:
			return startUp();
		
		case 1:
			return fuzz();
		
		case 2: 
			return options();
			
		case 3:
			return EXIT;
		}
		
		
		return true;
	}
	
	private boolean options(){
		System.out.println("\nSystem Options:");
		System.out.println("\t1. Set Time Gaps");
		System.out.println("\t2. Set Completeness");
		System.out.println("\t3. Show Current Settings");
		System.out.println("\t4. <-- Main Menu");
		System.out.print(": ");
		
		boolean validResponse = true;		
		
		int response = getMenuSelection();
		switch(response){
		
		case -1:
			return options();
		
		case 1:
			validResponse = setTimeGap();
			while(!validResponse){
				validResponse = setTimeGap();
			}
			System.out.println("\n--------------------\n" + 
					FuzzerData.getInstance().toString() + 
					"--------------------");
			return options();
			
		case 2:
			validResponse = setCompleteness();
			while(!validResponse){
				validResponse = setCompleteness();
			}
			System.out.println("\n--------------------\n" + 
					FuzzerData.getInstance().toString() + 
					"--------------------");
			return options();
			
		case 3:
			System.out.println("\n--------------------\n" + 
								FuzzerData.getInstance().toString() + 
								"--------------------");
			return options();
			
		case 4:
			return RUN;
			
		default:
			return options();
			
		}
	}
	
	private boolean fuzz(){
		
		System.out.println("\n--- Fuzz a Web Page --- ");
		System.out.println("Type 'BACK' to go back to the main menu");
		System.out.print("Enter a URL: ");
		
		Scanner scanner = new Scanner(System.in);
		try{
			String response = scanner.next();
			
			if (response.toLowerCase().equals("BACK")){
				return RUN;
			}
			
			
			WebFuzzer.fuzz(WebFuzzer.getBaseUrl(response), response, new HashSet<String>());
			
		}catch(InputMismatchException ime){
			System.err.println("Error: please enter a valid URL");
		}catch(Exception e){
			e.printStackTrace();
		}
		
		return RUN;
	}
	
	private boolean setTimeGap(){
		System.out.println("\n--- Set Time Gap ---");
		System.out.println("Type -1 to go back to the main menu");
		System.out.print("Please enter the time gap in milliseconds: ");
		
		Scanner scanner = new Scanner(System.in);
		int gap = 0;
		try{
			gap = scanner.nextInt();
			if(gap < 0){
				return true;
			}
		}catch(InputMismatchException ime){
			System.out.println("\nERROR: please enter a time gap number in milliseconds\n");
			return false;
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
		
		FuzzerData.getInstance().setTimeGap(gap);
		return true;
	}
	
	private boolean setCompleteness(){
		System.out.println("\n--- Set Completeness ---:");
		System.out.println("\t1. Complete discovery");
		System.out.println("\t2. Random discovery");
		System.out.println("\t3. <-- Main Menu");
		System.out.print(": ");
		
		int response = getMenuSelection();
		
		switch(response){
		case 1:
			FuzzerData.getInstance().setCompleteness(true);
			return true;
			
		case 2:
			FuzzerData.getInstance().setCompleteness(false);
			return true;
			
		case 3:
			return true;
			
		default:
			System.out.println("Not a valid option");
			return false;
		}
	}
	
	private int getMenuSelection(){
		Scanner scanner = new Scanner(System.in);
		int response;
		try{
			response = scanner.nextInt();
			
		}catch(InputMismatchException ime){
			System.err.println("Error: please enter the number corresponding to the option");
			response = -1;
		}catch(Exception e){
			e.printStackTrace();
			response = -1;
		}
		
		return response;
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
