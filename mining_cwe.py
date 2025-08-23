import argparse
import requests
from bs4 import BeautifulSoup
from googlesearch import search

def search_cwe_mitre(keyword, num_results=5, debug=False):
    """
    Searches Google for a keyword and crawls the titles of top N results from cwe.mitre.org.

    Args:
        keyword (str): The keyword to search for.
        num_results (int): The number of top results to crawl.
        debug (bool): If True, prints all URLs found during the search.

    Returns:
        list: A list of titles from cwe.mitre.org, or an empty list if none are found.
    """
    print(f"Searching for '{keyword} cwe' and filtering for the top {num_results} results from cwe.mitre.org...")
    query = f"{keyword} cwe"  # Append "cwe" to the keyword for better context
    
    cwe_links = []
    try:
        # We search through a larger number of results (e.g., top 30) 
        # to find the desired number of links from the target site.
        print("\n--- All Searched URLs (Debug Mode) ---") if debug else None
        for url in search(query, num_results=30):
            if debug:
                print(f"- {url}")
            if "cwe.mitre.org/data/definitions/" in url:
                cwe_links.append(url)
                # Stop once we have collected enough links
                if len(cwe_links) >= num_results:
                    break
    except Exception as e:
        print(f"An error occurred during Google search: {e}")
        return []

    if not cwe_links:
        print("No relevant links found on cwe.mitre.org within the top search results.")
        return []

    print(f"Found {len(cwe_links)} relevant links. Crawling titles...")
    
    titles = []
    for link in cwe_links:
        try:
            response = requests.get(link, timeout=10)
            response.raise_for_status()  # Raise an exception for bad status codes
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find the title tag
            title_tag = soup.find('title')
            if title_tag:
                title_text = title_tag.get_text()
                # Clean up the title by removing newlines, extra spaces, and the prefix
                cleaned_title = ' '.join(title_text.split()).replace("CWE - ", "").strip()
                titles.append(cleaned_title)
            else:
                titles.append(f"No title found for {link}")

        except requests.RequestException as e:
            print(f"Could not fetch or read page {link}: {e}")

    return titles

def main():
    """
    Main function to parse arguments and initiate the search.
    """
    parser = argparse.ArgumentParser(
        description="Mine CWE data from cwe.mitre.org based on a keyword.",
        epilog='Example:\n  python3 lab2/mining_cwe.py --keyword "Input Validation" -n 3',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--keyword", required=True, help="The keyword to search for (e.g., 'Type confusion', 'Input Validation').")
    parser.add_argument("-n", "--num-results", type=int, default=5, help="The number of top results to crawl from cwe.mitre.org.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode to print all searched URLs.")
    args = parser.parse_args()

    crawled_titles = search_cwe_mitre(args.keyword, args.num_results, args.debug)

    if crawled_titles:
        print("\n--- Crawled Titles ---")
        for i, title in enumerate(crawled_titles, 1):
            print(f"{i}. {title}")
    else:
        print("\nNo titles were crawled.")

if __name__ == "__main__":
    main()
