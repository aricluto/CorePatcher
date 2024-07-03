import os
import re
import logging
import shutil

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def find_file(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)
    return None


def modify_file(file_path):
    logging.info(f"Modifying file: {file_path}")
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    in_method = False
    method_type = None
    method_start_line = ""

    method_patterns = {
        "checkCapability": re.compile(r'\.method.*checkCapability\(.*\)Z'),
        "checkCapabilityRecover": re.compile(r'\.method.*checkCapabilityRecover\(.*\)Z'),
        "hasAncestorOrSelf": re.compile(r'\.method.*hasAncestorOrSelf\(.*\)Z'),
        "getMinimumSignatureSchemeVersionForTargetSdk": re.compile(
            r'\.method.*getMinimumSignatureSchemeVersionForTargetSdk\(I\)I'),
    }

    for line in lines:
        if in_method:
            if line.strip() == '.end method':
                modified_lines.append(method_start_line)  # Add the .method line
                if method_type == "checkCapability":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 4\n")
                    modified_lines.append("    const/4 v0, 0x1\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "checkCapabilityRecover":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 4\n")
                    modified_lines.append("    .annotation system Ldalvik/annotation/Throws;\n")
                    modified_lines.append("        value = {\n")
                    modified_lines.append("            Ljava/security/cert/CertificateException;\n")
                    modified_lines.append("        }\n")
                    modified_lines.append("    .end annotation\n")
                    modified_lines.append("    const/4 v0, 0x1\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "hasAncestorOrSelf":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 6\n")
                    modified_lines.append("    const/4 v0, 0x1\n")
                    modified_lines.append("    return v0\n")
                elif method_type == "getMinimumSignatureSchemeVersionForTargetSdk":
                    logging.info(f"Modifying method body for {method_type}")
                    modified_lines.append("    .registers 2\n")
                    modified_lines.append("    const/4 v0, 0x0\n")
                    modified_lines.append("    return v0\n")
                in_method = False
                method_type = None
            else:
                continue

        for key, pattern in method_patterns.items():
            if pattern.search(line):
                in_method = True
                method_type = key
                method_start_line = line  # Save the .method line
                break

        if not in_method:
            modified_lines.append(line)

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for file: {file_path}")


def modify_package_parser(file_path):
    logging.info(f"Modifying PackageParser file: {file_path}")
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    pattern = re.compile(
        r'invoke-static \{v2, v0, v1\}, Landroid/util/apk/ApkSignatureVerifier;->unsafeGetCertsWithoutVerification\(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;I\)Landroid/content/pm/parsing/result/ParseResult;')

    for line in lines:
        if pattern.search(line):
            logging.info(f"Found target line. Adding line above it.")
            modified_lines.append("    const/4 v1, 0x1\n")
        modified_lines.append(line)

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for file: {file_path}")


def modify_apk_signature_verifier(file_path):
    logging.info(f"Modifying ApkSignatureVerifier file: {file_path}")
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    pattern = re.compile(
        r'invoke-static \{p0, p1, p3\}, Landroid/util/apk/ApkSignatureVerifier;->verifyV1Signature\(Landroid/content/pm/parsing/result/ParseInput;Ljava/lang/String;Z\)Landroid/content/pm/parsing/result/ParseResult;')

    for line in lines:
        if pattern.search(line):
            logging.info(f"Found target line. Adding line above it.")
            modified_lines.append("    const p3, 0x0\n")
        modified_lines.append(line)

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for file: {file_path}")


def modify_exception_file(file_path):
    logging.info(f"Modifying exception file: {file_path}")
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    for line in lines:
        if re.search(r'iput p1, p0, Landroid/content/pm/PackageParser\$PackageParserException;->error:I', line):
            logging.info(f"Adding line above 'iput' in {file_path}")
            modified_lines.append("    const/4 p1, 0x0\n")
        modified_lines.append(line)

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for file: {file_path}")


def modify_apk_signature_scheme_v2_verifier(file_path):
    logging.info(f"Modifying ApkSignatureSchemeV2Verifier file: {file_path}")
    modify_invoke_static(file_path)


def modify_apk_signature_scheme_v3_verifier(file_path):
    logging.info(f"Modifying ApkSignatureSchemeV3Verifier file: {file_path}")
    modify_invoke_static(file_path)


def modify_apk_signing_block_utils(file_path):
    logging.info(f"Modifying ApkSigningBlockUtils file: {file_path}")
    modify_invoke_static(file_path)


def modify_invoke_static(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        modified_lines.append(line)
        if 'Ljava/security/MessageDigest;->isEqual([B[B)Z' in line:
            for j in range(i + 1, min(i + 4, len(lines))):
                if re.match(r'\s*move-result\s+(v\d+)', lines[j]):
                    variable = re.search(r'\s*move-result\s+(v\d+)', lines[j]).group(1)
                    logging.info(f"Replacing line: {lines[j].strip()} with const/4 {variable}, 0x1")
                    modified_lines[-1] = line  # Restore the original line
                    modified_lines.append(f"    const/4 {variable}, 0x1\n")
                    i = j  # Skip the move-result line
                    break
        i += 1

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for file: {file_path}")


def modify_strict_jar_verifier(file_path):
    logging.info(f"Modifying StrictJarVerifier file: {file_path}")
    modify_invoke_static(file_path)
    with open(file_path, 'r') as file:
        lines = file.readlines()

    modified_lines = []
    in_method = False
    method_start_pattern = re.compile(r'\.method private static blacklist verifyMessageDigest\(\[B\[B\)Z')
    target_line_pattern = re.compile(r'const/4 v1, 0x0')

    for line in lines:
        if in_method:
            if line.strip() == '.end method':
                in_method = False

        if method_start_pattern.search(line):
            in_method = True

        if in_method and target_line_pattern.search(line):
            logging.info(f"Found target line. Modifying it.")
            line = line.replace('const/4 v1, 0x0', 'const/4 v1, 0x1')

        modified_lines.append(line)

    with open(file_path, 'w') as file:
        file.writelines(modified_lines)
    logging.info(f"Completed modification for file: {file_path}")


def copy_and_replace_files(source_dirs, target_dirs, sub_dirs):
    for source_dir, sub_dir in zip(source_dirs, sub_dirs):
        for target_dir in target_dirs:
            target_policy_dir = os.path.join(target_dir, sub_dir)
            if os.path.exists(target_policy_dir):
                logging.info(f"Copying files from {source_dir} to {target_policy_dir}")
                for root, dirs, files in os.walk(source_dir):
                    for file in files:
                        src_file = os.path.join(root, file)
                        dst_file = os.path.join(target_policy_dir, os.path.relpath(src_file, source_dir))
                        dst_dir = os.path.dirname(dst_file)
                        if not os.path.exists(dst_dir):
                            os.makedirs(dst_dir)
                        shutil.copy2(src_file, dst_file)
                        logging.info(f"Copied {src_file} to {dst_file}")
            else:
                logging.warning(f"Target directory does not exist: {target_policy_dir}")


def modify_smali_files(base_directory):
    directories = [os.path.join(base_directory, f"classes{i}") for i in range(1, 6)]
    directories = [d for d in directories if os.path.exists(d)]
    
    if not directories:
        logging.error(f"No classes directories found in {base_directory}. Make sure you're in the correct directory.")
        return

    for directory in directories:
        logging.info(f"Processing directory: {directory}")
        files_to_modify = {
            'SigningDetails.smali': modify_file,
            'PackageParser$SigningDetails.smali': modify_file,
            'ApkSignatureVerifier.smali': lambda f: (modify_apk_signature_verifier(f), modify_file(f)),
            'ApkSignatureSchemeV2Verifier.smali': modify_apk_signature_scheme_v2_verifier,
            'ApkSignatureSchemeV3Verifier.smali': modify_apk_signature_scheme_v3_verifier,
            'ApkSigningBlockUtils.smali': modify_apk_signing_block_utils,
            'PackageParser.smali': modify_package_parser,
            'PackageParser$PackageParserException.smali': modify_exception_file,
            'StrictJarVerifier.smali': modify_strict_jar_verifier
        }

        for file_name, modify_func in files_to_modify.items():
            file_path = find_file(file_name, directory)
            if file_path:
                logging.info(f"Found file: {file_path}")
                modify_func(file_path)
            else:
                logging.warning(f"File not found: {file_name} in {directory}")

if __name__ == "__main__":
    base_directory = "classes"  # 修改为新的目录结构
    modify_smali_files(base_directory)
    
    source_dirs = ["assets/SettingsHelper", "assets/Utils"]
    target_dirs = [base_directory]
    sub_dirs = ["android/preference", "android/util"]
    copy_and_replace_files(source_dirs, target_dirs, sub_dirs)