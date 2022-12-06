import { RoleDto } from '../dto/user.dto';

export class RoleMapper {
  public mapToStrings(roles: RoleDto[]): string[] {
    const roleArray: string[] = [];
    roles.forEach((role) => {
      roleArray.push(role.name);
    });
    return roleArray;
  }
}
