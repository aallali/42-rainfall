
let c[68]

function m() {
    printf("%s - %d\n", c, time(0));
    return
}

function main() {   
    mOne = malloc(8) // 0x0804a008
    mOne[0] = 1
    mOne[1] = malloc(8) // 0x0804a018

    mTwo = malloc(8) // 0x0804a028
    mTwo[0] = 2
    mTwo[1] = malloc(8) // 0x0804a038

  
    strcpy(mOne[1], argv[1])
    strcpy(mTwo[1], argv[2])

    let password = fopen("/home/user/level8/.pass", "r")
    fgets(c, 68, password)
    
    puts("~~")
    return
}