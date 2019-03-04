# Umbrella Bulk Investigate API Lookup

This simple Python script uses the Umbrella Investigate API to perform a lookup in 1,000 bulk chunks at a time. This is more efficient than one at a time lookups.

[Umbrella Investigate API Documentation](https://docs.umbrella.com/investigate-api/docs)

The input is a simple text file with one domain, hostname or IP address.

> example.com  
> example.net  
> hostname.example.com  
> internetbadguys.com  
> 67.215.92.210  

- The Investigate API does not accept URLs.
- The script does not perform much input validation or check returned status code

Parse your date before sending it to the API to de-dupe the data sent to the API. The API has different tiers and the script will break when you hit the rate limit.
