int main(int argc(ebp+0x8), char **argv(ebp+12)) {

    if (atoi(argv[1] != 423){ 
        fwrite("No !\n", 1, 5, stderr)
    }
    else {

        arg1Execv = strdup("/bin/sh")
        arg2Execv = 0

        gid = getegid()
        uid = geteuid()

        setresgid(gid, gid, gid)
        setresuid(uid, uid, uid)

        execv("/bin/sh", [arg1Execv, arg2Execv])

    }
    return (0);
}