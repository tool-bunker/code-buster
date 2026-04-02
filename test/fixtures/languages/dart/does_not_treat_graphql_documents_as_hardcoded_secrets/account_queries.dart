const changeCustomerPassword = r"""
  mutation ChangePassword($input: ChangePasswordInput!) {
    changePassword(input: $input) { success }
  }
""";
const accessToken = '0123456789abcdef';
