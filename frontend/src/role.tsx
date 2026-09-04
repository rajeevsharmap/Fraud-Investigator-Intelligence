import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { setApiRole } from "./lib/api";
import type { Role } from "./types";

interface RoleContextValue {
  role: Role | null;
  selectRole: (role: Role) => void;
  clearRole: () => void;
}
const RoleContext = createContext<RoleContextValue | undefined>(undefined);

export function RoleProvider({ children }: { children: ReactNode }) {
  const [role, setRole] = useState<Role | null>(
    () => {
      const stored = sessionStorage.getItem("sentinel-role");
      const initialRole = stored === "JUNIOR" || stored === "SENIOR" ? stored : null;
      setApiRole(initialRole);
      return initialRole;
    },
  );
  useEffect(() => setApiRole(role), [role]);
  const selectRole = (next: Role) => {
    sessionStorage.setItem("sentinel-role", next);
    setApiRole(next);
    setRole(next);
  };
  const clearRole = () => {
    sessionStorage.removeItem("sentinel-role");
    setApiRole(null);
    setRole(null);
  };
  return (
    <RoleContext.Provider value={{ role, selectRole, clearRole }}>
      {children}
    </RoleContext.Provider>
  );
}
export function useRole() {
  const value = useContext(RoleContext);
  if (!value) throw new Error("useRole must be used within RoleProvider");
  return value;
}
