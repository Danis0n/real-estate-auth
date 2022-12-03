import { User, UserInfo, UserLogin, UserUrInfo } from '../proto/user.pb';

export class UserDto implements User {
  public id: string;
  public email: string;
  public phone: string;
  public siteLink: string;
  public userInfo: UserInfoDto | undefined;
  public userLogin: UserLoginDto | undefined;
  public userUr: UserUrInfoDto | undefined;
  public imageUrl: string;
  public date: string;
  roles: RoleDto[];
}

export class UserUrInfoDto implements UserUrInfo {
  address: string;
  description: string;
  inn: string;
  link: string;
}

export class UserLoginDto implements UserLogin {
  public login: string;
}

export class UserInfoDto implements UserInfo {
  public birthDate: string;
  public description: string;
  public firstName: string;
  public lastName: string;
  public enabled: boolean;
  public locked: boolean;
}

export class RoleDto {
  public name: string;
}
