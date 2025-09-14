---
layout: post
title: Go-basics
description:
category:
tags:
image:
---

## Variables 
### Declaration

```Go 
var varibaleName variableType
```

If no initialized they take their defaults, or a value of 0.

```Go 
var i int // Takes 0
var f float64 // Takes 0
var b bool // Takes false
var s string // takes ""
```

Simple declare: 

```Go 
var firstNum int = 1 

// For some Data types we can skip the variableType 
var secondNum = 20
```

Declare and assign: Avoid the `var` with `:=`

```Go
fourthNum := 30
fourthNum = 31  // OK — Assign a new value `31` to `fourthNum` 
fourthNum := 32 // compile-time error! This variable is already declared
```

Multiple declaration: 

```bash
// Variables are of the same type 

var isEnabled, hasValues, isOrdered bool

// Variables are with different types 

var (
    isEnabled bool
    hasValues bool
    isOrdered bool
    firstNum  int
    hello     string
)
```

### Constants

To declare a simple constant: 

```Go 
const pi = 3.141
const hubble int = 77
```

Or decalre multiple ones with different types:  

```Go 
const ( 
    hello = "Hello" 
    e = 2.718
)
```

Constants ensure our variables stay the same in the program flow:

```Go 
const HoursPerDay = 24
HoursPerDay = 25 // Cannot be assigned to `HoursPerDay`
```











