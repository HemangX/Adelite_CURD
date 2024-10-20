# GitLab SSH Key Setup Guide

## Introduction

This guide will help you create a GitLab account and configure SSH keys for secure access to your repositories.

## Prerequisites

- A GitLab account. If you don't have one, you'll create it in the steps below.
- Git installed on your local machine. [Download Git](https://git-scm.com/downloads).

## Step 1: Create a GitLab Account

1. Go to [GitLab](https://gitlab.com).
2. Click on the "Register" button.
3. Fill in the required details: Username, Email, and Password.
4. Complete the registration process by clicking the "Register" button.
5. Verify your email address by clicking on the verification link sent to your email.

## Step 2: Generate an SSH Key

1. Open your terminal (Git Bash on Windows, Terminal on macOS, or your preferred terminal on Linux).
2. Generate a new SSH key using the following command:

    ```sh
    ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
    ```

    - Replace `"your_email@example.com"` with the email address you used to register your GitLab account.
3. When prompted to "Enter a file in which to save the key," press Enter. This accepts the default file location.
4. You will then be prompted to enter a passphrase. It’s optional but recommended for added security. If you don’t want to set a passphrase, press Enter twice.

## Step 3: Add Your SSH Key to the SSH Agent

1. Start the SSH agent in the background:

    ```sh
    eval "$(ssh-agent -s)"
    ```

2. Add your SSH private key to the SSH agent:

    ```sh
    ssh-add ~/.ssh/id_rsa
    ```

## Step 4: Add Your SSH Key to Your GitLab Account

1. Copy the SSH key to your clipboard:
    - On macOS, you can use the following command:

        ```sh
        pbcopy < ~/.ssh/id_rsa.pub
        ```

    - On Linux, you can use the following command:

        ```sh
        xclip -sel clip < ~/.ssh/id_rsa.pub
        ```

    - On Windows (Git Bash), you can use the following command:

        ```sh
        cat ~/.ssh/id_rsa.pub | clip
        ```

2. Log in to your GitLab account.
3. In the top-right corner, click on your profile picture and go to "Settings."
4. In the left sidebar, click on "SSH Keys."
5. Paste your SSH key into the "Key" field.
6. Add a title to your SSH key for easy identification (e.g., "My Laptop SSH Key").
7. Click the "Add key" button.

## Step 5: Test Your SSH Connection

1. Open your terminal.
2. Test your SSH connection with the following command:

    ```sh
    ssh -T git@gitlab.com
    ```

3. If you've set up everything correctly, you should see a message like:

    ```sh
    Welcome to GitLab, @yourusername!
    ```

You have successfully configured your GitLab account with SSH keys. You can now clone, pull, and push repositories using SSH.
