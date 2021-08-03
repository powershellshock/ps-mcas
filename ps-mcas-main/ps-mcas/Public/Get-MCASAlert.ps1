<#
.Synopsis
   Gets alert information from your Cloud App Security tenant.
.DESCRIPTION
   Gets alert information from your Cloud App Security tenant and requires a credential be provided.

   Without parameters, Get-MCASAlert gets 100 alert records and associated properties. You can specify a particular alert GUID to fetch a single alert's information or you can pull a list of activities based on the provided filters.

   Get-MCASAlert returns a single custom PS Object or multiple PS Objects with all of the alert properties. Methods available are only those available to custom objects by default.
.EXAMPLE
    PS C:\> Get-MCASAlert -ResultSetSize 1

    This pulls back a single alert record and is part of the 'List' parameter set.

.EXAMPLE
    PS C:\> Get-MCASAlert -Identity 572caf4588011e452ec18ef0

    This pulls back a single alert record using the GUID and is part of the 'Fetch' parameter set.

.EXAMPLE
    PS C:\> (Get-MCASAlert -ResolutionStatus Open -Severity High | where{$_.title -match "system alert"}).descriptionTemplate.parameters.LOGRABBER_SYSTEM_ALERT_MESSAGE_BASE.functionObject.parameters.appName

    ServiceNow
    Box

    This command showcases the ability to expand nested tables of alerts. First, we pull back only Open alerts marked as High severity and filter down to only those with a title that matches "system alert". By wrapping the initial call in parentheses you can now extract the names of the affected services by drilling into the nested tables and referencing the appName property.

.FUNCTIONALITY
   Get-MCASAlert is intended to function as a query mechanism for obtaining alert information from Cloud App Security.
#>
function Get-MCASAlert {
    [CmdletBinding()]
    param
    (
        # Specifies the credential object containing tenant as username (e.g. 'contoso.us.portal.cloudappsecurity.com') and the 64-character hexadecimal Oauth token as the password.
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credential = $CASCredential,
        
        # Fetches an alert object by its unique identifier.
        [Parameter(ParameterSetName='Fetch', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern({^[A-Fa-f0-9]{24}$})]
        [Alias("_id")]
        [string]$Identity,

        # Filters results based on desired cri
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [string]$Filter,
        
        # Specifies the property by which to sort the results. Possible Values: 'Date','Severity', 'ResolutionStatus'.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet('Date','Severity')]
        [string]$SortBy,

        # Specifies the direction in which to sort the results. Possible Values: 'Ascending','Descending'.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet('Ascending','Descending')]
        [string]$SortDirection,

        # Specifies the maximum number of results to retrieve when listing items matching the specified filter criteria.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateRange(1,100)]
        [int]$ResultSetSize = 100,

        # Specifies the number of records, from the beginning of the result set, to skip.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateScript({$_ -gt -1})]
        [int]$Skip = 0
    )
    begin {
    }
    process {
        # Fetch mode should happen once for each item from the pipeline, so it goes in the 'Process' block
        if ($PSCmdlet.ParameterSetName -eq 'Fetch')
        {
            try {
                # Fetch the item by its id
                $response = Invoke-MCASRequest -Credential $Credential -Path "/api/v1/alerts/$Identity/" -Method Get
            }
            catch {
                throw "Error calling MCAS API. The exception was: $_"
            }
            
            try {
                Write-Verbose "Adding alias property to results, if appropriate"
                $response = $response | Add-Member -MemberType AliasProperty -Name Identity -Value '_id' -PassThru
            }
            catch {}
            
            $response
        }
    }
    end {
        if ($PSCmdlet.ParameterSetName -eq  'List') # Only run remainder of this end block if not in fetch mode
        {
            # List mode logic only needs to happen once, so it goes in the 'End' block for efficiency

            $body = @{'skip'=$Skip;'limit'=$ResultSetSize} # Base request body

            if ($SortBy -xor $SortDirection) {throw 'Error: When specifying either the -SortBy or the -SortDirection parameters, you must specify both parameters.'}

            # Add sort direction to request body, if specified
            if ($SortDirection) {$body.Add('sortDirection',$SortDirection.TrimEnd('ending').ToLower())}

            # Add sort field to request body, if specified
            if ($SortBy) {$body.Add('sortField',$SortBy.ToLower())}

            # Get the matching items and handle errors
            try {
                $response = Invoke-MCASRequest -Credential $Credential -Path "/api/v1/alerts/" -Body $body -Method Post
            }
            catch {
                throw "Error calling MCAS API. The exception was: $_"
            }
            
            $response = ($response.content | ConvertFrom-Json).data

            try {
                Write-Verbose "Adding alias property to results, if appropriate"
                $response = $response | Add-Member -MemberType AliasProperty -Name Identity -Value '_id' -PassThru
            }
            catch {}
            
            $response
        }
    }
}