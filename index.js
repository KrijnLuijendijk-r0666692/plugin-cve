// > index.js
const webserver = require('./webserver'); // include the webserver we just made
const request = require('request');       // request to write our endpoints
const app = webserver();                  // instantiate the webserver
require('dotenv').config(); // expose the .env file as environment variables. 

app.get('/datasets', function(req, res) {

	//var vendorlist = ['microsoft'];
	var datasets = [];
	
		request.get({
			uri: "http://cve.circl.lu/api/browse/microsoft",
			json: true
		}, function(error, products){
			//console.log(products.body);
			if (error)
       			return res.status(500).end('Internal Server Error');
       		var set = products.body.product.map(function(product){
       			return {
       				id: product,
       				name: `microsoft - ${product}`,
       				description: `Vulnerability list for ${product}`,
       				columns: [
       				{id: 'id', name: {en: 'Id'}, type: 'hierarchy'},
       				{id: 'published', name: {en: 'Published on'}, type: 'datetime'},
       				{id: 'cvss', name: {en: 'Cvss'}, type: 'numeric'},
       				{id: 'summary', name: {en: 'summary'}, type: 'hierarchy'}
       				]
       			}
       		})
       		//console.log(set);
       		datasets.push(set);
       		return res.status(200).json(datasets);
		});
		

	//console.log(datasets);


	
  
})





app.post('/query', function(req, res) {
	// code that retrieves the actual data upon a query 

	request.get({
    uri: `http://cve.circl.lu/api/search/microsoft/${req.body.id}`,
    json: true
  },(error, cves) => {
    if (error)
      return res.status(500).end('Internal Server Error');
    var CVE = cves.body.map(function(cve) {
      return [cve.id, cve.Published, cve.cvss, cve.summary];
    });
    return res.status(200).json(CVE);
  });
})