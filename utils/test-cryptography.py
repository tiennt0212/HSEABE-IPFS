from charm.toolbox.pairinggroup import PairingGroup, GT
from ABE.ac17 import AC17CPABE
from ABE.bsw07 import BSW07


def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    # for i in range(0, 10):
    #   print (pairing_group.random(GT))

    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # run the set up
    (pk, msk) = cpabe.setup()
    print("\n===========================================================\n")
    print("PK: ", pk)
    print("\n===========================================================\n")
    print("MSK: ", msk)
    # generate a key
    attr_list = ['READ', 'WRITE']
    key = cpabe.keygen(pk, msk, attr_list)

    print("\n===========================================================\n")
    print("KEY: ", key)

    # plaintext = pairing_group.random(GT)
    # plaintext="Hello world!"

    # print("\n===========================================================\n")
    # print("plaintext: ", plaintext)

    # print("\n===========================================================\n")
    # plaintext_encode = plaintext.encode('utf-8')
    # print("plaintext_encode: ", plaintext_encode)

    # choose a random message
    msg = pairing_group.random(GT)
    # msg = plaintext[0][0]

    # msg = [pairing_group.deserialize(plaintext_encode)]

    print("\n===========================================================\n")
    print("MSG: ", msg)

    print("\n===========================================================\n")
    msg_srl = pairing_group.serialize(msg)
    print("MSG_serialize: ", msg_srl)

    print("\n===========================================================\n")
    print("MSG_deserialize: ", pairing_group.deserialize(msg_srl))

    # generate a ciphertext
    # policy_str = '((ONE and THREE) and (TWO OR FOUR))'
    policy_str = '((OWNER) OR (READ) OR (READ and WRITE))'
    ctxt = cpabe.encrypt(pk, msg, policy_str)
    # print("\n===========================================================\n")
    # print("CTXT: ", ctxt)

    # decryption
    rec_msg = cpabe.decrypt(pk, ctxt, key)

    # print("\n===========================================================\n")
    # print("REC_MSG: ", rec_msg)

    if debug:
        if rec_msg == msg:
            print ("Successful decryption.")
        else:
            print ("Decryption failed.")


if __name__ == "__main__":
    debug = True
    main()
