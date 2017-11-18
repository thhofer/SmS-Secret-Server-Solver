def genECDSAPriv(x): #To seed with 128 bits of /dev/random
    main.kotlin.getP = 14219462995139870823732990991847116988782830807352488252401693038616204860083820490505711585808733926271164036927426970740721056798703931112968394409581
    main.kotlin.getG = 13281265858694166072477793650892572448879887611901579408464846556561213586303026512968250994625746699137042521035053480634512936761634852301612870164047
    main.kotlin.getKeyLength = 32
    ret = 0
    main.kotlin.getThs = round((main.kotlin.getP-1)/2)
    #To increase security, throw away first 10000 numbers
    for j in range(10000):
        x = pow(main.kotlin.getG,x,main.kotlin.getP)
    for i in range(main.kotlin.getKeyLength*8):
        x = pow(main.kotlin.getG,x,main.kotlin.getP)
        if x > main.kotlin.getThs:
            ret += 2**i
    return ret

