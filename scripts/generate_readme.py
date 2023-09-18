import os
import sys
    
ctf_name_tag = "[[CTF NAME]]"
challenges_tag = "[[CHALLENGES]]"
challenge_name_tag = "[[CHALLENGE NAME]]"
challenge_link_tag = "[[CHALLENGE LINK]]"

template = f"""\
# {ctf_name_tag}

## challenges

{challenges_tag}

"""

challenge_template = f"- [{challenge_name_tag}]({challenge_link_tag})"

def readme_generator(ctfname, challenges):
    def f(c):
        (name, link) = c
        return challenge_template.replace(challenge_name_tag, name).replace(challenge_link_tag, link)
    challenges = '\n'.join(map(f, challenges))
    return template.replace(ctf_name_tag, ctfname).replace(challenges_tag, challenges)

def gen_ctf_readme(ctfdir):
    print("[+] processing {ctfdir}")
    files = os.listdir(ctfdir)
    ctfname = os.path.basename(ctfdir)
    challenges = []
    for f in files:
        if f == "README.md":
            check = input("It contains README.md. continue?: [y/N]")
            if check not in ["y", "Y"]:
                return
            continue
        
        challname = f.split(".")[0]
        link = os.path.basename(f)
        challenges.append((challname, link))
    data = readme_generator(ctfname, challenges)
    with open(os.path.join(ctfdir, "README.md"), "w") as f:
        f.write(data)


def main():
    '''
    produces a simple README structured like this
    ```
    # CTF NAME

    - [CHALL1 NAME](link)
    - [CHALL2 NAME](link)
    ...

    ```
    '''

    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <target directory1> ...")
        return
    for d in sys.argv[1:]:
        gen_ctf_readme(d)

if __name__ == "__main__":
    main()