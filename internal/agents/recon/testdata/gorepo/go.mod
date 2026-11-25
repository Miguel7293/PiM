module example.com/demo

go 1.23

require example.com/direct v1.2.3
require (
 example.com/transitive v0.4.0 // indirect
 example.com/old v1.0.0
)

replace example.com/old => example.com/new v1.1.0
replace example.com/direct => ../local
