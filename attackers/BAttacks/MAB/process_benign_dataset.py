import sys, os
import pefile

def main():
    EXE_PATH = "The path to the directory containing benign PE files"
    CONTENT_PATH = '../../../dataset/benign_section_content/'

    list_section_content = []
    
    list_exe = os.listdir(EXE_PATH)
    list_exe.sort()
    list_name = []
    for exe in list_exe:
        print(EXE_PATH + exe)
        try:
            pe = pefile.PE(EXE_PATH + '/' + exe)
            for section in pe.sections:
                PointerToRawData = section.PointerToRawData
                SizeOfRawData = section.SizeOfRawData
                Name = section.Name.split(b'\0',1)[0].decode('utf-8')
                list_name.append(Name)
                Characteristics = section.Characteristics
                output_path = CONTENT_PATH + exe + '|' + Name + '|' + str(SizeOfRawData)
                print(output_path, PointerToRawData, SizeOfRawData)
                with open(EXE_PATH + exe, 'rb') as fp_in:
                    fp_in.seek(PointerToRawData)
                    content = fp_in.read(SizeOfRawData)
                    with open(output_path, 'wb') as fp_out:
                        fp_out.write(content)
        except Exception as e:
            print(e)

if __name__ == '__main__':
    main()