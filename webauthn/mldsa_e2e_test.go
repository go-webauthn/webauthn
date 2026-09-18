//go:build go1.27

package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// The vectors in this file are ceremony responses captured from webauthn.io against an authenticator which
// implements the ML-DSA parameter sets, and are the same responses SimpleWebAuthn verifies in its own suite. They
// are here because nothing this library generates itself can show that it agrees with a real authenticator about
// how an AKP credential public key and an ML-DSA signature are encoded: a vector produced by this library would
// carry the same misreading into both the writing and the reading of it.
//
// The registration vector for ML-DSA-44 and the assertion vector describe the same credential, so the two are
// chained rather than verified separately. That is what closes the loop: the credential public key this library
// decodes from a real authenticator's attested credential data is the key a real authenticator's signature is then
// verified against.
//
// Each attestation statement is of the none format. Vectors carrying an attestation statement made with an ML-DSA
// attestation key are not published anywhere this library can take them from, so the x5c path for these algorithms
// is covered by the constructed chain in TestPackedFormat_BasicAttestationMLDSA instead.

const (
	testMLDSARPID   = "webauthn.io"
	testMLDSAOrigin = "https://webauthn.io"

	// testMLDSAUserHandle is the user handle the assertion vector carries, which the user the ceremonies run
	// against must own for the response to be attributed to it.
	testMLDSAUserHandle = "webauthnio-ml-dsa-44"
)

const (
	// The registration vector for ML-DSA-44.
	testMLDSA44RegistrationID                = "-EM9FDFIdFVeqWdTycRjoZVN2ZS4vnVE-MBpg7k0pl4jpuqj4GnMCW3Wqlm2WWI2PQ"
	testMLDSA44RegistrationChallenge         = "4l8disV6VitGCg_EJvCNx7V92QLtBn_RYq9tTBEZ7j4B5hZI9kijJ2InLxQNRYVlgLROF3nfj80Yi7MPhXQwjw"
	testMLDSA44RegistrationAttestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkFoHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wxQAAAAQAAAAAAAAAAAAAAAAAAAAAADH4Qz0UMUh0VV6pZ1PJxGOhlU3ZlLi-dUT4wGmDuTSmXiOm6qPgacwJbdaqWbZZYjY9owEHAzgvIFkFIC4AIUrgARve17AEk0W30POluaL08p91eLXkktSjmAlmZdNTWhtUFj3wkseZEt4xpmWarG28Za86i7yq-B4df3uOuq3zQVTKOQUWJLWGJ3-wUUuyywPtkdgSqzQdcli6xMgwnVqh9r6FVL9Xp7x3kgjUVDqhux_k1D2d4ts2zqi1rUrSF6FNX139g3dd1VnUNQrMLdrwohR9CmE0fZ6Am4Df_OV2JxOrUEPzMFi5SeBcrU1oSj2lX_91gY179PO0wIOtTa1KzWvwOYa_KjOj9Ow16AtmsXrcpL-jYW4_bFn4kpT9G-vDG4qPFDpint62g0DDjEt7JrF288aIZXOpsbVmnjw2_O_5pFFvFpH32gD7_NdmvE6PSymNxPcTCnMzY3xv5wJXiEDhO21E85n78Oay4k7PzWHvzQxlJldIYw-9TfKZXqZa6sIbE-LyZj_Y2FV1Owd4WLvKCNcO-IIP3XFcZ7__XPZtAsBTJ5Z5w18jRnlMNKTygva-F2Ec65tA2skED9PnVyS_WjtZN5VjbhuU-D9DIDXEgUjitdcXWbCruDjxaBwjuDFXOI9cYdp4n-KWCZGJdX9QFHDGkvX6zDXupFrFV1q1JeKCayuMJjL3Z44AMF2UtjNODzhlviE8neX5NSfXdf36FWGFER6D6YCGGvooW8EBCx8OLPRNGGwoKBrEflr_ISYIdyw8-rDkAG0-bka_ulzfg8uTY8BXNu0HhqsteUPni4HlhUXMb0yI1DbLi5hTTkpBEBfmjzTJ8JMDe9sOOaqU2PrOzvIs5c7fx_VBqQZbF6amei2Y41okZJWwW0LWNvL2JQ_Yj9deHMczichCHWVX3uCL-SfPL3AaLeWLPjTAejU-H1Lnn2jWQeHtiRxBL1eleZNmJVqFbrgclcMXirM6rrmPrsbFe41fDF3Hm1KgcKkpZMPSICijfDCT4csVeLDxmsg9aDYwboxigOVHZa-zAmePLBZrPJIWDNEHNBG9CdEG-RfeshvnRbPerB1zLzA9jP-Jj55_Xd4igau4FEc7dLWgyn2b2Q3aMAaDnKCzEScd301WeuZtutm6flzqDPCUTJnoniUHuO__bALWkzIxe5rHW6wQ_wPBEX32bQNN-gtI6_yiw-UTwu3egro3tDp7ZzHkMSslF9FHD7divbmeEzsE8N4iOwO5kWFt2jY9VpjGXAhyCcGZtWU68SzllOpWzvuacFjlE5KZ_c4nHhYdaphJAjXvbkog-vGUwjffCXe9gQhIliwPzREtccZdgyLKiBAlypp0pwVKe6disU9-2kflk_BXPRf1PkBEqO41ySFZWLb6eSij9FrIXtPAo4RFmeKPLoYT-ce3gi8_XftVv7MDl9s0hoFlgh5vTh1xMdpxEt-6BxdesEF3zJycxNY4QFVkUKE78geXogQFz2QE7kW4ncTXjq4IydHOKX9Bp2P8uGcCJ6dzW3PFE-Zurf1klV-rkvT7xE-Tds7CPeWkrRr_Ckhn6rQ2Z3-Sjz5bgIRHiBnd0iZfm6ZgD77nVHY7ztaSmUQ7JWbeFSz0eoYExgXi7HfSdV77DlHxIjcNlrSh58SGWfkSwUVboOUJKy_B3EbBDeweqn1pf7QIjAJnYL7WiogmAku2UxEBQijtPAusmyhLf0_aTEFFc3zdGutHim3dzAKfJucy2aBm8ViQxY_U1N26WVO6sfui7dZVhqkQniZLCq8N_xqEMqWV6utksRHOvITvB_SqmeDacy2ZfiSogU8K5G2ha2NyZWRQcm90ZWN0Ag"
	testMLDSA44RegistrationClientDataJSON    = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNGw4ZGlzVjZWaXRHQ2dfRUp2Q054N1Y5MlFMdEJuX1JZcTl0VEJFWjdqNEI1aFpJOWtpakoySW5MeFFOUllWbGdMUk9GM25majgwWWk3TVBoWFF3anciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"

	// The registration vector for ML-DSA-65.
	testMLDSA65RegistrationID                = "S903soghFo9Bmu9i4Styf5hLEPFkxu_Ma8Nm65BiZdBt1pGqF4dB2cth6wknrCMk6A"
	testMLDSA65RegistrationChallenge         = "rQM3_HtwB63gl8EoLqrM4iPCmQ3siW9U7Rutnw9qGMZT8lWAETIaZcFEw6j2Qw40fDGZW4QrbisBjoRbeXidLw"
	testMLDSA65RegistrationAttestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkIIHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wxQAAAAIAAAAAAAAAAAAAAAAAAAAAADFL3TeyiCEWj0Ga72LhK3J_mEsQ8WTG78xrw2brkGJl0G3WkaoXh0HZy2HrCSesIyToowEHAzgwIFkHoNsFUCfZJHghYZMYm8P_ANG6RtvE1VKrK5_ER7yE512V3UmGjIlYVOSIMebtBorke1TBvjuBi8PBKAQs4w16SJ7ijjT8r9ClCt_aHcFDTjz49s3jLIwqL08wPD1qJy6vrdkTES-mrU6rJG16RAhInZh4ie98DGZhBBaOUBIrnIy9QvceP9Qi8-4GBLcBiS-cL_da94kK6XZJXJLy1Qm-LfDPdsoph0YHGSfueYBJy41Tpu6oU4QStJ90r_E86dxQj_nd0uDPuwbje_lIrF0sbedrkNXVOwh00m-PK05fmwb-wpUUGsRq2o7gvm3oCMSxm-1dwYHKdBWjf8y_E34kiQ_ZeZTsA1yXSKci7kCEGGXqLDIE0chka6hY6xZZlEA89Cbqv_HPAN29t0_70144qDuXb4nLfQ7XY-uoS5OBP_W0rkc3lc3r0spe0c9ZO8lHEGFbX8PyP98gkM2z61kDstai23k6OjLTKMvuulKNYbTxCLTj37BpiNxnqqq5bs0dkG9eO5yHpqBwH4sm4qUXRsG-ZS9_TvfiEtKahjU5uAhZWOYs71CcCIfSKSD_swPg-7VKUwzSpYq2BwlExdBpDHL-ghogYAOgf5FNs9fUNHLRmFpOUDnmUAeX7iNrtA7Tu3BygNv8JWUCTuWllzT2GQpD70xJMAjKxMkvXrqqCfJrFTQt0FscjqjZqcP8xyiaCo0nPILaGChuakL0XBgh-Fi5YkulKsaDd5orLnka4063lpn0jdxvy1yk0p4tfFRmEBnankCmk44ZvbKJQRMsDcydqgjK0vpQxVWbf1r-73GHNvliWw1ajYmqUe2uwDGdLBBCUbDeqcmrRJYnX6g8W-vlh3VLWGBlHodtGWUEkJxY7RmArf2UeEBDGWj3QoGJTfQYUzXg91Y2fSmgi2b3ZPzUg8h92JKMCpbvJr6PLANCFGf3RviLYnNuU0Zn8czC80tsUtxkkzLN0iFkRvT_WPha6lbuwIlMKNXkXRbkph79wSBasp81aqzgPd4Yq9LDrZIrNI6q7ZbYGoF03C0Digqdj_f6aUxxIteIuCWm-z_xHY9Czo4VHo0V8YnTFyZj3HDX1S8NZ_odvP_GZcmvgLmUhsWRmMxs2WEJFDrcgFR-tK9KLYf29gGI0lPsSJtnho_GLUKX5-tdojlBVEcVO6rPieS8-bCu8B4BeyduYAnDgHdxBAUBfm2um7ZIDTl_n6g-bZb-TxMvsGbIO3NK99QylHqSRFK68PX-yvDZjsZlblKZSe8WsSG_RVNrWGYiKjVpsqZy61eXoSE5ySCOQvAdlpTEdb7F5C1_USkpdyuyR5BGXtFizf2V60wDPbjOrr3Yz1CuUB_DRDvbvc4GKIAzCZDR6MC3oIJjQ2Z81pzv8ZrXq5LhhSdda2TTBtckM-BRyLJHh7ZkHY03DFLqfGSn-KUzGlk2fUWFdJ4zlT4AquxJTKJYBQlWt6tOgGV8MB5j5DUuwgbw9a7dx_jRW8AZps4O96y85c-rQS7e9g5noatqxq1vZp6X-vTTMZXF-nx1sgSHEgoN5bm30fsrMP0MvaahDZaEIV3o8kj7o-uRM8VGyXVHm3qhtQdYIwzrjWBCA96t7x75zgmgxIWJbzIgfay3WHeguFIwW844OaO_zq3C43tDCXU0ahWiTjEPeYqAVDGlifqOPEFpiO5t9lvwjU5upQybkhnwLzFvaUVCgzGu_2bm7geO5NphNee8lz7Rbi4r8VBCzDYBLcjeqMiUCduCQH8y3mo3Z3F4V0qqAUHM6w_hMr8V9K_mGNeSYDEv52bBHxfywJkcqSTq3TVkPXicWfb1VHJroZ47LdAQ-jlGJaTnJEfHeY5VHHjy9gQ6_px7iZ9JggN0SIJDbSdHXHxkdFbSgMnEHo8N3YFoB-oEO5AKX1CJ3kELg8gO-nybVMC4ktDqk5dAAglVcp5GQC8gY_EP92LAXt4MFHRkM9g4zgZHVlqKLqbPPYngB9nOAM-8rZGo3Nez0zB7m5EFDkxV8PoD0k2omrJEqWrSDd9swG6kFiH4-5MV-8csaka-PO0kwS-KZmbh7R-OhJlmKujJw6nxYDfUaPeXQs6QsFqU83BZxl5gZGr8LPmqP83i1tEk1RQd_pwFa-ks7GmMvWQuyK2PnaW9cXfH-0-Z-jetukzac8KqTOkdedYmeTPW9oHlGmPvAEBvoGNQeUzw5Q_uwBv60LdbEpy61iiTQNEy7eKDxylHJld41P9vTTh1om6TEWGmHJ1BQ5YLoZ1E_X4dnMZGZUtcK4Ym_81jHMdRw4NkdQhPtPFe5kfPYMdIn_QeAIVIS_KPyo07t_9BhrDfRBirl_BfAGpEdVuwZQYO-x-jZ-0WGXptAp1TpmAVjD2Y-Gwx4xRL-Y-M7NTaTAeZpEB6_UdQU8UUL_DfQLxlF6dE4Px_0xmPAXBNtZJIWcdOIOIpnjP2vvT39x4SgoS1Ij7udQZUoidhA6M6_bwOT3uimKVm31vLH-tN_N3eMgQj8Db2Wj6htO0Ysk58ueKGN17UruWYPnktWiR-M3hZs5mJKlxHeVwTEcZgkIqYM14Hg0IB8M41ICy1vhrEzO9aQ1Cwn36srly2-h_coWtjcmVkUHJvdGVjdAI"
	testMLDSA65RegistrationClientDataJSON    = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiclFNM19IdHdCNjNnbDhFb0xxck00aVBDbVEzc2lXOVU3UnV0bnc5cUdNWlQ4bFdBRVRJYVpjRkV3NmoyUXc0MGZER1pXNFFyYmlzQmpvUmJlWGlkTHciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"

	// The registration vector for ML-DSA-87.
	testMLDSA87RegistrationID                = "OsaaaMgQ7ihU9iAzryPBOLK3PYsghC98pX4ZaDzXzY1NsiXgH-afxzClNy3oRPK1YA"
	testMLDSA87RegistrationChallenge         = "JsGsBtHMYXARUIoR1rHvam63XDdRDzaLKbndrscpgU0qKFpJA0xeuv__ufk_5mgjIabEZneO9V32YWyMshWmEA"
	testMLDSA87RegistrationAttestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkKoHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wxQAAAAEAAAAAAAAAAAAAAAAAAAAAADE6xppoyBDuKFT2IDOvI8E4src9iyCEL3ylfhloPNfNjU2yJeAf5p_HMKU3LehE8rVgowEHAzgxIFkKIPB266vR3jhFEvswhiiULf6og2993LKO8euC16EFiq3z9bud2jKbB6Zw5xm7vOQUIZyCsN18qxjPRoI142swvpDA4rApAGZb028Qgyrz4eQTfueiBsy-GRJ5IN2rsVlFcz3enbYWgh_UWQDSMA9wNfTPJZPz6T-z8KTz60szO8Mn4UG1kLQ5YSV47b6LqJVnrsWzTFe0nylAkpHMtBHS3UNjhoEYNc6HyL9ehBoLGs3Z0IPusTYdcZ8LA4icQsoX3X8XEORW4MV5x1l9qwC_6-iZ4rAsbSUsUMDyB_h-FKn7TP9X8x_IA6fCDuUIL2vMWwVj-yNtVbw_NqJkm5OePjPQzh04F6wxLd4y0qeLZA7ycjADjACLKa_IJVFMgxx_7nJ2pbHKOYfqJzAnCg9nqMUVeonWBunJatFABgwKR4-cNzV6pcn1bL4haHbHdblbZ7f0nv7-DPz75BaZhDaurOBLBHGDh5bC856v0EkPOfRO81pKBa-EyT3OkZ7qejOMeEZpbvhCvECisLwbKo8lcAR0gaqHLNGEXcqNUFXVbLzdfcrDd_FMD-kBByAlGdMswYANrFpLVpmkJEGQ_Eqow99ZcyBvdwxtxCQT3X4i3rFRhB8FGP9JAkODC67U-EWIMyWF2VIseVZkxMngwsZAm327jFIoOfupWeUGjpGORhOvI6OPA2VzR6wrFjkfsM_6bt8VMHIpo5lUtGMKND5K2M3fRCFvQqPWW7MOQ83b-6qfa-GcGKzVfojGd6uwVJjgDDJldMMve8OCTktiwIJ4h-n5ObGRvlJQ7etgycCwXINUkb1KFZovgUQnujhjK4f0M0Ib76scKCmYX_UtexSCf09jkwQRgtBh3BnzJrgILfErMmfK2Z1z5wWUV4MX2oXcNkWyGGH1kCLnzXu1qveFsry7Hf27DyceNIAzuqkrtcsJgw7ePhXHz0AgdYo8qyQmXSPfhAEWiwtCZ5MbUKmxn-8pGiRKqUtbzpYTNwTpj2PdpzK1zvAAHubIxi5XXi_JEJL8h2HOmkRJLLo26GDfNV0n0SRGhujW65LNdAU7ggrgzEcdbkRPNX0vsyax0ZBr9HXs-GnlR_4ySugcgGVIdj5xv7xsvDnfy-bVPMLgOP1nCLvZROJwMAA3XOAD9SKjsQMLKQjsiZHIelWzOxHrr360wowj3jclxQUD9XgDtNfff6MjiS3rsBO05ECyF3bMcsjsRak7GStJ2MFBAbdESryKek1z-2g4ahqUuO0LGeX7Klzi110XpqN9VYrrvUNP6seqm_V48PinvDDPsfsHqC2ZFPRtWv3rcZt6RbA9KLsqXqWphMqr3MZm8k69E2ZiWn-wFHXMBWTKzrRxtiBOHk4mcygTOIn2AsjVMO8GCglyJlUluN0eQWiapr48lnE3EetPNGxq86wn28wPQhC56jcLkNHq-RDEjycvFzUzgoa4i1mJCW038vHGPH8-CLYGggPeSOnL-zZMRtw-jDaMR5HHc95FlsTLlMVbpnb-eCGT2-khduVx4HdpdoTJHfT4PNQTTVnVY6N5vUP9x5jXq6p7Zwvl_VpWR9jxZZcO1KIoi5ozIgE5XqNF-NKumoouAfpZWxauhdkBgUL86WnH3zQah8hHY1d7QeZGcfo4fx8S0NiTsVa9wIat3BBlck3HmwbduMP7Web7Rhf_Pj3lfhVrZ0p5nKFizbacQcK4mVwCM8MPaFEN6xAIwqLzFYWIwc_sUKxRq2WLg3RvIbBl0-TesJfzSPWMJGcq4iropcn-JW8XFQVJyf4KBFuwImpXq1wrOalOjIgAk5nGiYxLxK3feeOoG22uBNkfg_qJfqzGX_o3BMaXZyvydAQCY36z2SbFEme3LxsdC-vYUi6iVuxVdpL2gXm3OtNiI4iGvBNoJvGzHZwSh0-GpZbqdN_wZMFimvz8R75O2PPXSkmyLyDmNxDaSGsnZeQ4BCyD63YLnhFlWzG7VBIdAr570KEz9dhU6ozJ6iP_mtETAImGWB733xuIeZ2D3Aj-Q9l2s2xfPKqPXkvOe2OjC288A86T5l5_9mANfFgfLCjdsMwSQau_EOkrvmPkaHacBoWPfPMWwyBJSnF6jNPHoaRBtFba6Ld-f4ThJyaza52JLza1xIviFn37XzFCvLRXrpI6wghURUP2vk-dMs1l8hQRH3RIvcBIqctikAL3NuY8otXhQUw-1QjkIv2llYeXARAhE-2bIvATrf7FrVN4hJBbU3uesAyYvpG9NN8XGztoptOotFP_pYH67yUaiYJXmnPTzWEzk0F5kUhZTvy7ZlwKMv2EINrXDc0q1Dx0MJnJSe02PQr2C0RzR0zkTi00-y104KimThbs7QLRgnke7BlaJtgJH7T-KETvLqs6Ogpptzntt6whM8lesXUvQr5jm3l0WLCSo1W8-q-Vxfo8v6cbkHxsP_xoM43uOsklCuypxyVfnBRVGsgL9W5_7TaZTWMdfoak9fwMjd8j1lu6oXmOiu96TQ8vpETLuN4A1AOnFS1grl1dBZ-kUoKV_vu4ZFDkacK20S8Q5X-WcM5zKmpVUWL3oyWg3VNxSDu_16LLPQ7pYfgS9dNftCHnOjYUgY2Co_xD0ejB83G-a3aC-OSBwo7NtOHTfh6gysbSzBwsJ0Tw9GyCRRLqpu4YsWGkJXiblfGI-2zH8aGm0GZLz84p8FqRCipTbMt8yjFjKDoCp3iBpUTfMs3uON28otSpkgF5XPIwihK7O0Fu8tw-DMLXbbxMDxyAhto3xGb7Q1KT_-hc4SrghI4dy_Evm095K6Fr3sHsQ_oVck2xd71r4e_uPCXFpiHbvImwtuE94XyGgy9y1l2TvRa6P1ZpKh-ccxv_v1TZdf3gIn04M7kio46WfIiURcS6aoVfCef1pUpGRcVgxnwWrJw_8tu7MZUukXmM3SA7dezKIe446WE6BiXay7TNBu9yThxldO7ooK6udljaap3pEyejRWNJ83zSVv5OwjlvDtC4joCHJ6BejJh60OM0KeiMniTJftrV4F3ZRMgn7MdbJtUYOY4SoodNAfPEBr5n_6n7ZCT4uBAsLtyYwHmzjIR1qZxOVfH98C2xOrp6ZWFMiAlrJkPDoiD8sMMB6oWA2aT_vPcixKBQqNqrkeKScusIiThNCTrlK5AkDe_AqUEW1qu8E6Qbb-7YLCrhqIbMmg5eGKXZ7c9j94jd-rShqUz2seWaLAXkKi-VMsUdTnlgvQ-A_6IRd8wM30BpVQeDuS-AE3cfnw8poVsuaPsMU5me9Ro1um1GUEU8mLzSw6ZMgHlbFapubropKvU-2-s0nozxQzs7bh4NkPF5gZ1zuf7xNXcPV3uodzJnmtBNn7lcfJK69serkxLEKOa7IiS2osGQlxDh9mwwMip7fuVPhN9ZWadhWnrFlWfdKzv082WxErNeM_SslKaeg8UJPzRYllQ1szvS3pYyt8u3JSX2z6FrY3JlZFByb3RlY3QC"
	testMLDSA87RegistrationClientDataJSON    = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSnNHc0J0SE1ZWEFSVUlvUjFySHZhbTYzWERkUkR6YUxLYm5kcnNjcGdVMHFLRnBKQTB4ZXV2X191ZmtfNW1naklhYkVabmVPOVYzMllXeU1zaFdtRUEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
)

const (
	// The assertion vector, made by the credential the ML-DSA-44 registration vector registers.
	testMLDSAAssertionChallenge         = "Ji15971jSESa9haCUYb7s_pMhV8DNNwYT8Wb5zbEo151Ab7s_MuT-_MIjnousfaF2Q3emFAx7GkpXkTUmMicTQ"
	testMLDSAAssertionAuthenticatorData = "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAACA"
	testMLDSAAssertionClientDataJSON    = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSmkxNTk3MWpTRVNhOWhhQ1VZYjdzX3BNaFY4RE5Od1lUOFdiNXpiRW8xNTFBYjdzX011VC1fTUlqbm91c2ZhRjJRM2VtRkF4N0drcFhrVFVtTWljVFEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
	testMLDSAAssertionSignature         = "e7L-Xli-2lj9ZlP2s26sbrvFGLkVrz74BZnDsLW-7HOhj7AcEl5Zgtm3VLvLtcrfqyKE0PTuFrswsikm7t6ddhxXphxWcSo4ggarl6ODQk8NdPCYoFhoK8qwpqKZKmJAl9xDsJE1HAudrWLgq_747JV4QmGLizK0_oJgGM7WLd5xVYvKsl14odBFjU_ZBCrjB0UHIMg8aAq1727yZnY1eiNeF_sEmci_pigYCo-MbxbHmQWPp-U75sGSPPfK0soN2-29_aIxRO4Fg8P37WrwVUrEFdG2PFNgAhcM-ljjyv3mkCfsLUiQNuS-a0cn6MeygREc2HBwE6ChS351-dpNTbkfnb-o1fA6suP1sh3-i7YZrEn9e2J7UZxIAEJPpmuKxYFA4Fj0lAGUhi3lvnkWPOnS8BUjPr5q5z5iEbyL4MokDP75G723Tyy-5L8u1pLmlSLiuwvuW5MBkEhjVVj0RpVSnCoqzwE9A9ZmqZx5wv5gQEi4hAA64mSoXGdUZ5EGkPGrrIDjGyIOrLjuHOSZ6hjyioZvMA1nCQJ76oaL5-Pn1FR1VTurI5ccTWrDAo5sHuo8uGjx9bsyy_aMT3Nzosu29PArTm0AkJFd7INXky0L9itCmhujSnali9zTO8UuwV0G8sZeB2BG4VZN2nkjT1Ib8VeBnSMTlIFVOI2JHlD9kePZuV3nCuAvK8j5qH5OPJoEeJzuxGHP2k7f0941kzyW9sjBaD90HEusVGGgST0qWigEKU3kKaO_Du5ZngcqlmKnnFVKXQk5mEV5nFs9ia76sKe9FKYUp_ZxsVFATcjXETW5GuXF1qIj0ZTCSmhn8V_cqEH29fQWyy9qxNa6kkKc4koZUP36B-h5yVawIDdfyjl-VueUvUyEunPv1EyqXQaf9bo-WThxD_5v3Bd2sYTOI__0PIsUvCASjZJMQU4jpwyXoR2EsLWDRD4fsAxLmdao0iXNxdlH0Ys2MqkXkkMbIylccEHkFjbm_VB5tPYQkFRqqRX13KUyYqqTpaT6MdD8IpltlzJxcNLd9mazUvOfSaf5ho2FFtv8TMubekKU8b92MoPQpjeS1DJ9y2pvMrtIiZP0Lm0WTeniN6luRfUN-4v5GU6FPajkOPLNV9OXJKLREhrA_SvbDldSF9RtWZOqIk1WeTlbnEWlejtwWFoLSScCSfExu6bu_vv9NKK-E8mTWF8_f4bCvlZQp58BEsTHrZuBiQzH34Z5wPeOZuuQlqbAquIS4_W6z_XmNW-d4FhIp2U3y9sYC7wpo1M7N7MB3HKwAliPVgsNHBRI4ZLZ-dL3FCyCMThKJqQMNrMcRif_Mm5Du--Atjn1UH2u2gAxiBA6IY7uSlSn-OJEO-m8qeif8zsdvVhXtJMxNAWZHhQ4QuRFgjuDgxy1nVuhGHdmXi6tseiiC2NQ9iqGuBRetexfz84R93RVSbKMkYlvBU1KPe8ARVf_N52C1KC9F2b3Uo5To9iD2lXShcsGkQkcAX5gjmhy4jrmTv5-pUJYAHa6A9Vorr59D7-Y-CVvVX59YJB9-kMT8wzHQdj2XimbcLKnS5Z4BKsMMEIt01LVkdHcBP9tKBQ20e-Kmf25wsUr9TqFa7ukQEhfLwgflIBbobAJoGKFC2_3fIKaEBuoAOoErASxPClLNAbBqG1JAdrAq9Ki3WC46aN4b-Q6ykfbk2azLAxOzFftJuhLWGLLCkOxbxjfaUrRJ51h8Dwrpy2xBT1qWurNnfFTrzScouK-R8G4SfsyaSiejiaLYLsWZVCcpeH_S8cqQuBFCMpQfxiPn2reOgMFhSzbdSDkzwUTQsjGq94QTs7bdS0LlyRb4OUa0s3szGSIa7n4vQ10uc9gzHlDxEqgaKSpPlVDyvZs58GC3PCZ2HJiiVbuc508_rV1xuydd7asPlyaOAMXImKPxp7d6rAGLbDOQOKS4U9sr6wKQVPnfPqg7TvmtuXTJS5Y_M6mutU7Bn8y6qmbjt5EtoETTSORHfx71ySMLZ8zxveJdsaNow6lfjvI0myk8oSDIucRar1j9G2m13B3K2Kr0URBweH6JkJz3Z7mYFTe09B6GMzIOcPoaYzzJP_PSrpuAfvb6V0AwVCX_HixF2qkCvcdrLyvGaGkkkYh32T2Renu7QWj8Wz06MvimWYCA4pB8SPJpjyw8mNZHOWJXgkI8hgD90O_rDF8mhEIMbDtfTZdOPjekS1a7-LNUGM6ajWLzDehU5YQBzTuGwgoPd2RV0E68iYR6QplHTmhh5vToa7eHvbQrYn8NUzJ6CP5YXcoxl7H9HsQ3AXDHmCtZ3e5p4FLV-Lz64_hVJWaTLOgHecFGAFqXMmnp1BtoKlzwbMnXaFMVaT1T7CkC_XZsoggQA1WFO3vFuXpnw4D6BPNGTmEZrEmINmfBVeFHB4SHDPJXDYX4wwTK8kgUpCHSI8ozIYFy0nw4uJqhkAYjXnvbEeCPsPkf7SPGS7xujgIdlYbtizeg-op2ZyI020Jt-hx2GogXRD_bsNcHaToWZ90fTI8M_Y1-F8iMJG4OnxinHlHnTj7R6wRuM2AZ4-Ov_yhd9w6yXenoKh56RReHCbYAvGCt3aDDyOrcX9WX7VePrBHH3C9ubCwj3PNcuP16or5ho6XRNlXC1s63J99dgi42FWatXeYdUvvcmK7fKxFZWSCXko-cArTT1KqgucxXg8wMk7gaGSwfb2j3pNt1hf4y5MOJQ-HbS0uhuywUbBiHBe8ns6FzUJpM4T8sNXAfbslBk1nIYU9BCMn1Veqw8puCYcwkjWJgxrKU_d2Jx0b8DKpIbbdFKkrdR4vAGRTJ74IgWPuk7wZTSWCddJAB4Q1PU1nbXO3MsxxzlQrWXY1jD9Zp3E69NEUss4qMTT6u5W-RG6RB6ge6sOt47l40v3IO-1LgsCwJtFyQzks0msArf0MSSQ9HreubNnjYqaMOqgUleX4-a0P8BhQwOhwt7C6zyGCnbcBiQx0RWAs0mvf-k5mgqn9Ij5mpGoGVV5L4OhBdY6pm51h7v02bgoWlzUzZHImgBhQtkx0jlBM9XeCIo4t8EQ4ZbqGmLsbj3CTu7KZbc9uQJkWyXSov2WWMvzZfOgCHbizXOGazd47v44BDRMXIiUmJzI1ZXiFkqPB0NftBw80ZnCHlpeq1Nzq8_QQHiM2R1SEsc_T1QQcSlJTVmBpdnqesbv9AAAAAAAAAAAAAAAAAAAAAAAAAAAAABMhLDo"
	testMLDSAAssertionUserHandle        = "d2ViYXV0aG5pby1tbC1kc2EtNDQ"

	// testMLDSAAssertionCredentialPublicKey is the credential public key as the authenticator returned it
	// at registration, which the registration vector is asserted against.
	testMLDSAAssertionCredentialPublicKey = "owEHAzgvIFkFIC4AIUrgARve17AEk0W30POluaL08p91eLXkktSjmAlmZdNTWhtUFj3wkseZEt4xpmWarG28Za86i7yq-B4df3uOuq3zQVTKOQUWJLWGJ3-wUUuyywPtkdgSqzQdcli6xMgwnVqh9r6FVL9Xp7x3kgjUVDqhux_k1D2d4ts2zqi1rUrSF6FNX139g3dd1VnUNQrMLdrwohR9CmE0fZ6Am4Df_OV2JxOrUEPzMFi5SeBcrU1oSj2lX_91gY179PO0wIOtTa1KzWvwOYa_KjOj9Ow16AtmsXrcpL-jYW4_bFn4kpT9G-vDG4qPFDpint62g0DDjEt7JrF288aIZXOpsbVmnjw2_O_5pFFvFpH32gD7_NdmvE6PSymNxPcTCnMzY3xv5wJXiEDhO21E85n78Oay4k7PzWHvzQxlJldIYw-9TfKZXqZa6sIbE-LyZj_Y2FV1Owd4WLvKCNcO-IIP3XFcZ7__XPZtAsBTJ5Z5w18jRnlMNKTygva-F2Ec65tA2skED9PnVyS_WjtZN5VjbhuU-D9DIDXEgUjitdcXWbCruDjxaBwjuDFXOI9cYdp4n-KWCZGJdX9QFHDGkvX6zDXupFrFV1q1JeKCayuMJjL3Z44AMF2UtjNODzhlviE8neX5NSfXdf36FWGFER6D6YCGGvooW8EBCx8OLPRNGGwoKBrEflr_ISYIdyw8-rDkAG0-bka_ulzfg8uTY8BXNu0HhqsteUPni4HlhUXMb0yI1DbLi5hTTkpBEBfmjzTJ8JMDe9sOOaqU2PrOzvIs5c7fx_VBqQZbF6amei2Y41okZJWwW0LWNvL2JQ_Yj9deHMczichCHWVX3uCL-SfPL3AaLeWLPjTAejU-H1Lnn2jWQeHtiRxBL1eleZNmJVqFbrgclcMXirM6rrmPrsbFe41fDF3Hm1KgcKkpZMPSICijfDCT4csVeLDxmsg9aDYwboxigOVHZa-zAmePLBZrPJIWDNEHNBG9CdEG-RfeshvnRbPerB1zLzA9jP-Jj55_Xd4igau4FEc7dLWgyn2b2Q3aMAaDnKCzEScd301WeuZtutm6flzqDPCUTJnoniUHuO__bALWkzIxe5rHW6wQ_wPBEX32bQNN-gtI6_yiw-UTwu3egro3tDp7ZzHkMSslF9FHD7divbmeEzsE8N4iOwO5kWFt2jY9VpjGXAhyCcGZtWU68SzllOpWzvuacFjlE5KZ_c4nHhYdaphJAjXvbkog-vGUwjffCXe9gQhIliwPzREtccZdgyLKiBAlypp0pwVKe6disU9-2kflk_BXPRf1PkBEqO41ySFZWLb6eSij9FrIXtPAo4RFmeKPLoYT-ce3gi8_XftVv7MDl9s0hoFlgh5vTh1xMdpxEt-6BxdesEF3zJycxNY4QFVkUKE78geXogQFz2QE7kW4ncTXjq4IydHOKX9Bp2P8uGcCJ6dzW3PFE-Zurf1klV-rkvT7xE-Tds7CPeWkrRr_Ckhn6rQ2Z3-Sjz5bgIRHiBnd0iZfm6ZgD77nVHY7ztaSmUQ7JWbeFSz0eoYExgXi7HfSdV77DlHxIjcNlrSh58SGWfkSwUVboOUJKy_B3EbBDeweqn1pf7QIjAJnYL7WiogmAku2UxEBQijtPAusmyhLf0_aTEFFc3zdGutHim3dzAKfJucy2aBm8ViQxY_U1N26WVO6sfui7dZVhqkQniZLCq8N_xqEMqWV6utksRHOvITvB_SqmeDacy2ZfiSogU8K5G0" //nolint:gosec // This is a public key from a captured ceremony response, not a credential.
)

// mldsaRegistrationVector is a registration ceremony response captured from webauthn.io, along with the values the
// Relying Party held in session when it was made.
type mldsaRegistrationVector struct {
	alg               webauthncose.COSEAlgorithmIdentifier
	id                string
	challenge         string
	attestationObject string
	clientDataJSON    string
}

var mldsaRegistrationVectors = []mldsaRegistrationVector{
	{
		alg:               webauthncose.AlgMLDSA44,
		id:                testMLDSA44RegistrationID,
		challenge:         testMLDSA44RegistrationChallenge,
		attestationObject: testMLDSA44RegistrationAttestationObject,
		clientDataJSON:    testMLDSA44RegistrationClientDataJSON,
	},
	{
		alg:               webauthncose.AlgMLDSA65,
		id:                testMLDSA65RegistrationID,
		challenge:         testMLDSA65RegistrationChallenge,
		attestationObject: testMLDSA65RegistrationAttestationObject,
		clientDataJSON:    testMLDSA65RegistrationClientDataJSON,
	},
	{
		alg:               webauthncose.AlgMLDSA87,
		id:                testMLDSA87RegistrationID,
		challenge:         testMLDSA87RegistrationChallenge,
		attestationObject: testMLDSA87RegistrationAttestationObject,
		clientDataJSON:    testMLDSA87RegistrationClientDataJSON,
	},
}

// TestMLDSARegistrationVectors asserts that a registration response made by an authenticator using each of the
// ML-DSA parameter sets registers, and that the credential which comes out of it names the algorithm the
// authenticator used and carries a public key this library can parse.
func TestMLDSARegistrationVectors(t *testing.T) {
	for _, vector := range mldsaRegistrationVectors {
		t.Run(vector.alg.String(), func(t *testing.T) {
			w, user, session, response := mldsaRegistrationCeremony(t, vector)

			credential, err := w.CreateCredential(user, session, response)

			require.NoError(t, err)
			require.NotNil(t, credential)

			assert.Equal(t, mldsaDecode(t, vector.id), credential.ID)
			assert.Equal(t, "none", credential.AttestationFormat)

			key, err := webauthncose.ParsePublicKey(credential.PublicKey)

			require.NoError(t, err)
			require.IsType(t, webauthncose.AKPPublicKeyData{}, key)

			akp, _ := key.(webauthncose.AKPPublicKeyData)

			assert.Equal(t, int64(vector.alg), akp.Algorithm)
			assert.Equal(t, int64(webauthncose.AKP), akp.KeyType)

			public, err := akp.ToPublicKey()

			require.NoError(t, err)
			assert.NotNil(t, public)

			t.Run("ShouldRejectAlgorithmNotRequested", func(t *testing.T) {
				// The credential parameter lists which do not request the ML-DSA parameter sets are the ones a
				// Relying Party which has not asked for them uses, so a response naming one must not register.
				unrequested := session
				unrequested.CredParams = CredentialParametersRecommendedL3()

				credential, err := w.CreateCredential(user, unrequested, response)

				assert.Nil(t, credential)
				require.EqualError(t, err, "Invalid attestation format")
			})

			t.Run("ShouldRejectAnotherChallenge", func(t *testing.T) {
				other := session
				other.Challenge = base64.RawURLEncoding.EncodeToString([]byte("a challenge the response was not made over"))

				credential, err := w.CreateCredential(user, other, response)

				assert.Nil(t, credential)
				require.ErrorContains(t, err, "Error validating challenge")
			})
		})
	}
}

// TestMLDSACeremoniesEndToEnd asserts that an assertion made by a real ML-DSA credential verifies against the
// credential this library registered from that same authenticator's registration response.
//
// The registration and the assertion are chained rather than checked apart so that the credential public key under
// test is the one this library decoded, not one restated by the test.
func TestMLDSACeremoniesEndToEnd(t *testing.T) {
	vector := mldsaRegistrationVectors[0]

	require.Equal(t, webauthncose.AlgMLDSA44, vector.alg)

	w, user, session, response := mldsaRegistrationCeremony(t, vector)

	credential, err := w.CreateCredential(user, session, response)

	require.NoError(t, err)
	require.NotNil(t, credential)

	// The two vectors describe the same credential, which is what makes chaining them meaningful.
	assert.Equal(t, mldsaDecode(t, testMLDSAAssertionCredentialPublicKey), credential.PublicKey)

	assertion, err := protocol.ParseCredentialRequestResponseBytes(mldsaAssertionBody(t, vector.id, testMLDSAAssertionSignature))

	require.NoError(t, err)

	userID := []byte(testMLDSAUserHandle)

	owner := &defaultUser{id: userID, credentials: []Credential{*credential}}

	validated, err := w.ValidateLogin(owner, SessionData{UserID: userID, Challenge: testMLDSAAssertionChallenge}, assertion)

	require.NoError(t, err)
	require.NotNil(t, validated)

	assert.Equal(t, credential.ID, validated.ID)
	assert.Equal(t, uint32(8), validated.Authenticator.SignCount)

	t.Run("ShouldRejectTamperedSignature", func(t *testing.T) {
		sig := mldsaDecode(t, testMLDSAAssertionSignature)

		sig[0] ^= 0xff

		assertion, err := protocol.ParseCredentialRequestResponseBytes(mldsaAssertionBody(t, vector.id, base64.RawURLEncoding.EncodeToString(sig)))

		require.NoError(t, err)

		validated, err := w.ValidateLogin(owner, SessionData{UserID: userID, Challenge: testMLDSAAssertionChallenge}, assertion)

		assert.Nil(t, validated)
		require.ErrorContains(t, err, "Error validating the assertion signature")
	})

	t.Run("ShouldRejectSignatureAgainstAnotherCredentialKey", func(t *testing.T) {
		// The ML-DSA-65 vector is a different credential of a different parameter set, so a signature made by the
		// ML-DSA-44 credential must not verify against it.
		_, otherUser, otherSession, otherResponse := mldsaRegistrationCeremony(t, mldsaRegistrationVectors[1])

		other, err := w.CreateCredential(otherUser, otherSession, otherResponse)

		require.NoError(t, err)

		wrong := *credential
		wrong.PublicKey = other.PublicKey

		assertion, err := protocol.ParseCredentialRequestResponseBytes(mldsaAssertionBody(t, vector.id, testMLDSAAssertionSignature))

		require.NoError(t, err)

		validated, err := w.ValidateLogin(&defaultUser{id: userID, credentials: []Credential{wrong}}, SessionData{UserID: userID, Challenge: testMLDSAAssertionChallenge}, assertion)

		assert.Nil(t, validated)
		require.ErrorContains(t, err, "Error validating the assertion signature")
	})
}

// mldsaRegistrationCeremony returns everything the registration half of a vector's ceremony needs, configured for
// the Relying Party the response was captured against.
func mldsaRegistrationCeremony(t *testing.T, vector mldsaRegistrationVector) (w *WebAuthn, user User, session SessionData, response *protocol.ParsedCredentialCreationData) {
	t.Helper()

	w = &WebAuthn{Config: &Config{RPID: testMLDSARPID, RPOrigins: []string{testMLDSAOrigin}}}

	userID := []byte(testMLDSAUserHandle)

	session = SessionData{
		UserID:     userID,
		Challenge:  vector.challenge,
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: vector.alg}},
	}

	response, err := protocol.ParseCredentialCreationResponseBytes(mldsaRegistrationBody(t, vector))

	require.NoError(t, err)

	return w, &defaultUser{id: userID}, session, response
}

func mldsaRegistrationBody(t *testing.T, vector mldsaRegistrationVector) []byte {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"id":    vector.id,
		"rawId": vector.id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": vector.attestationObject,
			"clientDataJSON":    vector.clientDataJSON,
		},
	})

	require.NoError(t, err)

	return body
}

func mldsaAssertionBody(t *testing.T, id, signature string) []byte {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": testMLDSAAssertionAuthenticatorData,
			"clientDataJSON":    testMLDSAAssertionClientDataJSON,
			"signature":         signature,
			"userHandle":        testMLDSAAssertionUserHandle,
		},
	})

	require.NoError(t, err)

	return body
}

func mldsaDecode(t *testing.T, s string) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(s)

	require.NoError(t, err)

	return decoded
}
