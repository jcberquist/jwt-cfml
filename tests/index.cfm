<cfsilent>
<cfscript>
testbox = new testbox.system.Testbox();
param name="url.reporter" default="simple";
param name="url.directory" default="specs";
args = {reporter: url.reporter, directory: url.directory};
if (structKeyExists(url, 'bundles')) args.bundles = url.bundles;
results = testBox.run(argumentCollection = args);
</cfscript>
</cfsilent>
<cfcontent reset="true">
<cfoutput>
<h4 class="bg-primary text-white p-3">
	#server.coldfusion.productname# #structKeyExists(server, 'lucee') ? server.lucee.version : server.coldfusion.productversion#
</h4>
#trim(results)#
</cfoutput>
