var vm = require('.');

var vm = new vm.NodeVM({                   
  require: true,                          
  requireExternal: true                   
});                                       

vm.run('console.log(require("foobar"));', "/data/myscript.js");
